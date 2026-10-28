use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    path::{Path, PathBuf},
};

use axum::{
    Json,
    extract::{ConnectInfo, State},
    http::StatusCode,
};
use certifex_core::{
    HandoffActivationChallenge, HandoffActivationRequest, HandoffActivationResponse,
    HandoffApproval, HandoffApprovalResponse, HandoffOfferResponse, IdentityError,
    NodeRegistration, RegistrationResponse,
};
use serde::{Deserialize, Serialize};
use tokio::fs;
use tracing::info;

use crate::acme::RenewalSchedule;

use super::{
    AppState, Controller, ControllerError, StoredNode, durable_replace, same_csr_public_key,
    unix_now,
};

const HANDOFF_OFFER_TTL_SECONDS: i64 = 7 * 24 * 60 * 60;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredHandoff {
    id: String,
    target: NodeRegistration,
    sources: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    approvals: BTreeSet<String>,
    #[serde(default)]
    prepared: Option<PreparedHandoff>,
    #[serde(default)]
    committing: bool,
    updated_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PreparedHandoff {
    certificate: certifex_core::CertificateBundle,
    renewal: Option<RenewalSchedule>,
}

impl StoredHandoff {
    fn ready(&self) -> bool {
        self.sources
            .keys()
            .all(|source| self.approvals.contains(source))
    }

    const fn expired(&self, now: i64) -> bool {
        !self.committing && self.updated_at.saturating_add(HANDOFF_OFFER_TTL_SECONDS) < now
    }

    fn moved_hostnames(&self) -> Vec<String> {
        self.sources
            .values()
            .flatten()
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    fn response(&self) -> HandoffOfferResponse {
        HandoffOfferResponse {
            offer_id: self.id.clone(),
            target_node_id: self.target.node_id.clone(),
            source_node_ids: self.sources.keys().cloned().collect(),
            hostnames: self.moved_hostnames(),
        }
    }
}

pub async fn load_handoffs(
    directory: &Path,
) -> Result<BTreeMap<String, StoredHandoff>, ControllerError> {
    fs::create_dir_all(directory).await?;
    let now = unix_now();
    let mut result = BTreeMap::new();
    let mut entries = fs::read_dir(directory).await?;
    while let Some(entry) = entries.next_entry().await? {
        if entry.path().extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let handoff = serde_json::from_slice::<StoredHandoff>(&fs::read(entry.path()).await?)?;
        if handoff.expired(now) {
            fs::remove_file(entry.path()).await?;
            continue;
        }
        result.insert(handoff.id.clone(), handoff);
    }
    Ok(result)
}

pub async fn offer(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(registration): Json<NodeRegistration>,
) -> Result<Json<HandoffOfferResponse>, (StatusCode, String)> {
    if let Err(error) = registration.validate() {
        return Err((StatusCode::BAD_REQUEST, error.to_string()));
    }
    if !peer.ip().is_loopback() && peer.ip() != registration.tailscale_ip {
        return Err((
            StatusCode::FORBIDDEN,
            format!(
                "handoff offer source {} does not match claimed Tailscale address {}",
                peer.ip(),
                registration.tailscale_ip
            ),
        ));
    }
    state
        .controller
        .offer_handoff(registration)
        .await
        .map(Json)
        .map_err(|error| controller_status(&error))
}

pub async fn approve(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(approval): Json<HandoffApproval>,
) -> Result<Json<HandoffApprovalResponse>, (StatusCode, String)> {
    if approval.offer_id.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "offer_id is required".to_owned()));
    }
    if let Err(error) = approval.source.validate() {
        return Err((StatusCode::BAD_REQUEST, error.to_string()));
    }
    if !peer.ip().is_loopback() && peer.ip() != approval.source.tailscale_ip {
        return Err((
            StatusCode::FORBIDDEN,
            format!(
                "handoff approval source {} does not match claimed Tailscale address {}",
                peer.ip(),
                approval.source.tailscale_ip
            ),
        ));
    }
    state
        .controller
        .approve_handoff(&approval)
        .await
        .map(Json)
        .map_err(|error| controller_status(&error))
}

pub async fn activate(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(activation): Json<HandoffActivationRequest>,
) -> Result<Json<HandoffActivationResponse>, (StatusCode, String)> {
    if activation.node_id.trim().is_empty() || activation.offer_id.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "node_id and offer_id are required".to_owned(),
        ));
    }
    if !peer.ip().is_loopback() && peer.ip() != activation.tailscale_ip {
        return Err((
            StatusCode::FORBIDDEN,
            format!(
                "handoff activation source {} does not match claimed Tailscale address {}",
                peer.ip(),
                activation.tailscale_ip
            ),
        ));
    }
    state
        .controller
        .activate_handoff(&activation)
        .await
        .map(Json)
        .map_err(|error| controller_status(&error))
}

fn controller_status(error: &ControllerError) -> (StatusCode, String) {
    let status = match error {
        ControllerError::HandoffNotFound(_) => StatusCode::NOT_FOUND,
        ControllerError::Io(_)
        | ControllerError::Json(_)
        | ControllerError::Cloudflare(_)
        | ControllerError::Acme(_)
        | ControllerError::Identity(_) => StatusCode::BAD_GATEWAY,
        _ => StatusCode::CONFLICT,
    };
    (status, error.to_string())
}

impl Controller {
    pub(super) async fn offer_handoff(
        &self,
        mut registration: NodeRegistration,
    ) -> Result<HandoffOfferResponse, ControllerError> {
        let _serial = self.reconcile.lock().await;
        self.validate_registration_scope(&registration).await?;
        self.prune_expired_handoffs().await?;
        self.reject_reserved_names(&registration).await?;
        let sources = self.active_conflicts(&registration).await;
        if sources.is_empty() {
            return Err(ControllerError::HandoffNotNeeded);
        }
        registration.installed_generation = None;

        let mut superseded = Vec::new();
        {
            let handoffs = self.handoffs.read().await;
            for handoff in handoffs.values() {
                if !handoff_target_matches(handoff, &registration)? {
                    continue;
                }
                if handoff.sources == sources || handoff.ready() {
                    return Ok(handoff.response());
                }
                superseded.push(handoff.id.clone());
            }
        }
        for id in &superseded {
            self.delete_handoff(id).await?;
        }
        if !superseded.is_empty() {
            let mut handoffs = self.handoffs.write().await;
            for id in superseded {
                handoffs.remove(&id);
            }
        }

        let now = unix_now();
        let id = loop {
            let candidate = format!("{:016x}{:016x}", fastrand::u64(..), fastrand::u64(..));
            if !self.handoffs.read().await.contains_key(&candidate) {
                break candidate;
            }
        };
        let handoff = StoredHandoff {
            id: id.clone(),
            target: registration,
            sources,
            approvals: BTreeSet::new(),
            prepared: None,
            committing: false,
            updated_at: now,
        };
        self.persist_handoff(&handoff).await?;
        self.handoffs
            .write()
            .await
            .insert(id.clone(), handoff.clone());
        info!(
            offer_id = %id,
            target_node_id = %handoff.target.node_id,
            sources = handoff.sources.len(),
            names = handoff.moved_hostnames().len(),
            "created hostname handoff offer"
        );
        Ok(handoff.response())
    }

    pub(super) async fn approve_handoff(
        &self,
        approval: &HandoffApproval,
    ) -> Result<HandoffApprovalResponse, ControllerError> {
        let _serial = self.reconcile.lock().await;
        self.prune_expired_handoffs().await?;
        let mut handoff = self
            .handoffs
            .read()
            .await
            .get(&approval.offer_id)
            .cloned()
            .ok_or_else(|| ControllerError::HandoffNotFound(approval.offer_id.clone()))?;
        if handoff.expired(unix_now()) {
            self.delete_handoff(&handoff.id).await?;
            self.handoffs.write().await.remove(&handoff.id);
            return Err(ControllerError::HandoffNotFound(approval.offer_id.clone()));
        }
        self.validate_registration_scope(&approval.source).await?;
        let source_id = &approval.source.node_id;
        let names = handoff
            .sources
            .get(source_id)
            .ok_or_else(|| ControllerError::HandoffApprovalNotSource(source_id.clone()))?;
        let source = self
            .nodes
            .read()
            .await
            .get(source_id)
            .cloned()
            .ok_or_else(|| ControllerError::HandoffApprovalNotSource(source_id.clone()))?;
        if source.registration.tailscale_ip != approval.source.tailscale_ip {
            return Err(ControllerError::HandoffApprovalAddressMismatch {
                node_id: source_id.clone(),
                expected: source.registration.tailscale_ip,
                actual: approval.source.tailscale_ip,
            });
        }
        for name in names {
            if !source.owns_hostname(name) || !approval.source.hostnames.contains(name) {
                return Err(ControllerError::HandoffOwnershipChanged(name.clone()));
            }
        }
        if let Some(name) = approval
            .source
            .hostnames
            .iter()
            .filter(|name| handoff.target.hostnames.contains(name))
            .find(|name| !names.contains(name))
        {
            return Err(ControllerError::HandoffReserved {
                name: name.clone(),
                node_id: handoff.target.node_id.clone(),
            });
        }

        handoff.approvals.insert(source_id.clone());
        if handoff.ready() {
            let current_sources = self.active_conflicts(&handoff.target).await;
            if current_sources != handoff.sources {
                return Err(ControllerError::HandoffSourcesChanged(handoff.id));
            }
            self.ensure_handoff_reservation_available(&handoff).await?;
        }
        handoff.updated_at = unix_now();
        self.persist_handoff(&handoff).await?;
        self.handoffs
            .write()
            .await
            .insert(handoff.id.clone(), handoff.clone());
        let remaining_node_ids = handoff
            .sources
            .keys()
            .filter(|source| !handoff.approvals.contains(*source))
            .cloned()
            .collect::<Vec<_>>();
        let ready = remaining_node_ids.is_empty();
        info!(
            offer_id = %handoff.id,
            source_node_id = %source_id,
            ready,
            "approved hostname handoff"
        );
        Ok(HandoffApprovalResponse {
            offer_id: handoff.id,
            ready,
            remaining_node_ids,
        })
    }

    pub(super) async fn reconcile_handoff(
        &self,
        registration: &NodeRegistration,
    ) -> Result<Option<RegistrationResponse>, ControllerError> {
        let mut matching = None;
        {
            let handoffs = self.handoffs.read().await;
            for handoff in handoffs.values() {
                if handoff_target_matches(handoff, registration)? {
                    matching = Some(handoff.clone());
                    break;
                }
            }
        }
        let Some(mut handoff) = matching else {
            return Ok(None);
        };
        if handoff.expired(unix_now()) {
            self.delete_handoff(&handoff.id).await?;
            self.handoffs.write().await.remove(&handoff.id);
            return Ok(None);
        }
        let missing = handoff
            .sources
            .keys()
            .filter(|source| !handoff.approvals.contains(*source))
            .cloned()
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            return Err(ControllerError::HandoffAwaitingApproval {
                offer_id: handoff.id,
                node_ids: missing,
            });
        }

        if handoff.prepared.is_none() {
            self.validate_handoff_sources(&handoff).await?;
            let previous = self.nodes.read().await.get(&registration.node_id).cloned();
            let (certificate, renewal) = self
                .certificate_for_registration(registration, previous.as_ref())
                .await?;
            handoff.prepared = Some(PreparedHandoff {
                certificate,
                renewal,
            });
            handoff.updated_at = unix_now();
            self.persist_handoff(&handoff).await?;
            self.handoffs
                .write()
                .await
                .insert(handoff.id.clone(), handoff.clone());
        }

        let prepared = handoff
            .prepared
            .as_ref()
            .ok_or_else(|| ControllerError::HandoffNotFound(handoff.id.clone()))?;
        Ok(Some(RegistrationResponse {
            certificate: Some(prepared.certificate.clone()),
            handoff_activation: Some(HandoffActivationChallenge {
                offer_id: handoff.id,
                generation: prepared.certificate.generation,
            }),
        }))
    }

    pub(super) async fn activate_handoff(
        &self,
        activation: &HandoffActivationRequest,
    ) -> Result<HandoffActivationResponse, ControllerError> {
        let _serial = self.reconcile.lock().await;
        let handoff = self
            .handoffs
            .read()
            .await
            .get(&activation.offer_id)
            .cloned()
            .ok_or_else(|| ControllerError::HandoffNotFound(activation.offer_id.clone()))?;
        if handoff.expired(unix_now()) {
            self.delete_handoff(&handoff.id).await?;
            self.handoffs.write().await.remove(&handoff.id);
            return Err(ControllerError::HandoffNotFound(
                activation.offer_id.clone(),
            ));
        }
        if handoff.target.node_id != activation.node_id
            || handoff.target.tailscale_ip != activation.tailscale_ip
        {
            return Err(ControllerError::HandoffActivationTargetMismatch {
                offer_id: handoff.id,
                node_id: activation.node_id.clone(),
            });
        }
        let prepared = handoff
            .prepared
            .as_ref()
            .ok_or_else(|| ControllerError::HandoffNotPrepared(handoff.id.clone()))?;
        if prepared.certificate.generation != activation.generation {
            return Err(ControllerError::HandoffActivationGenerationMismatch {
                offer_id: handoff.id,
                expected: prepared.certificate.generation,
                actual: activation.generation,
            });
        }

        let mut handoff = handoff;
        if !handoff.committing {
            handoff.committing = true;
            handoff.updated_at = unix_now();
            self.persist_handoff(&handoff).await?;
            self.handoffs
                .write()
                .await
                .insert(handoff.id.clone(), handoff.clone());
        }
        let mut registration = handoff.target.clone();
        registration.installed_generation = Some(activation.generation);
        self.commit_handoff(&handoff, &registration).await?;
        Ok(HandoffActivationResponse {
            offer_id: activation.offer_id.clone(),
        })
    }

    pub(super) async fn reject_hostname_conflicts(
        &self,
        registration: &NodeRegistration,
    ) -> Result<(), ControllerError> {
        self.reject_reserved_names(registration).await?;
        let conflicts = self.active_conflicts(registration).await;
        if let Some((node_id, names)) = conflicts.into_iter().next()
            && let Some(name) = names.into_iter().next()
        {
            return Err(ControllerError::NameCollision { name, node_id });
        }
        Ok(())
    }

    pub(super) async fn guard_source_relinquish(
        &self,
        registration: &NodeRegistration,
        previous: Option<&StoredNode>,
    ) -> Result<(), ControllerError> {
        let Some(previous) = previous else {
            return Ok(());
        };
        let handoffs = self.handoffs.read().await;
        let now = unix_now();
        for handoff in handoffs.values() {
            if handoff.expired(now) || !handoff.approvals.contains(&registration.node_id) {
                continue;
            }
            let Some(names) = handoff.sources.get(&registration.node_id) else {
                continue;
            };
            for name in names {
                if previous.owns_hostname(name) && !registration.hostnames.contains(name) {
                    return Err(ControllerError::HandoffSourceMustKeepServing {
                        offer_id: handoff.id.clone(),
                        name: name.clone(),
                    });
                }
            }
        }
        drop(handoffs);
        Ok(())
    }

    async fn active_conflicts(
        &self,
        registration: &NodeRegistration,
    ) -> BTreeMap<String, Vec<String>> {
        let nodes = self.nodes.read().await;
        let mut conflicts = BTreeMap::<String, Vec<String>>::new();
        for (node_id, node) in nodes.iter() {
            if node_id == &registration.node_id {
                continue;
            }
            for name in &registration.hostnames {
                if node.owns_hostname(name) {
                    conflicts
                        .entry(node_id.clone())
                        .or_default()
                        .push(name.clone());
                }
            }
        }
        drop(nodes);
        conflicts
    }

    async fn reject_reserved_names(
        &self,
        registration: &NodeRegistration,
    ) -> Result<(), ControllerError> {
        let handoffs = self.handoffs.read().await;
        let now = unix_now();
        for handoff in handoffs.values() {
            if handoff.expired(now)
                || !handoff.ready()
                || handoff.target.node_id == registration.node_id
            {
                continue;
            }
            if handoff
                .sources
                .get(&registration.node_id)
                .is_some_and(|names| {
                    names
                        .iter()
                        .all(|name| registration.hostnames.contains(name))
                        && registration
                            .hostnames
                            .iter()
                            .filter(|name| handoff.target.hostnames.contains(name))
                            .all(|name| names.contains(name))
                })
            {
                continue;
            }
            if let Some(name) = registration
                .hostnames
                .iter()
                .find(|name| handoff.target.hostnames.contains(name))
            {
                return Err(ControllerError::HandoffReserved {
                    name: name.clone(),
                    node_id: handoff.target.node_id.clone(),
                });
            }
        }
        drop(handoffs);
        Ok(())
    }

    async fn validate_handoff_sources(
        &self,
        handoff: &StoredHandoff,
    ) -> Result<(), ControllerError> {
        let nodes = self.nodes.read().await;
        let target = nodes.get(&handoff.target.node_id);
        for name in &handoff.target.hostnames {
            for (node_id, node) in nodes.iter() {
                if node_id == &handoff.target.node_id || !node.owns_hostname(name) {
                    continue;
                }
                if !handoff
                    .sources
                    .get(node_id)
                    .is_some_and(|names| names.contains(name))
                {
                    return Err(ControllerError::HandoffOwnershipChanged(name.clone()));
                }
            }
        }
        for (source_id, names) in &handoff.sources {
            let source = nodes
                .get(source_id)
                .ok_or_else(|| ControllerError::HandoffOwnershipChanged(source_id.clone()))?;
            for name in names {
                let target_already_owns = target.is_some_and(|target| target.owns_hostname(name));
                if !(source.owns_hostname(name)
                    || source.released_hostnames.contains(name) && target_already_owns)
                {
                    return Err(ControllerError::HandoffOwnershipChanged(name.clone()));
                }
            }
        }
        drop(nodes);
        Ok(())
    }

    async fn ensure_handoff_reservation_available(
        &self,
        candidate: &StoredHandoff,
    ) -> Result<(), ControllerError> {
        let handoffs = self.handoffs.read().await;
        if let Some((name, node_id)) = conflicting_ready_handoff(&handoffs, candidate, unix_now()) {
            return Err(ControllerError::HandoffReserved { name, node_id });
        }
        drop(handoffs);
        Ok(())
    }

    async fn commit_handoff(
        &self,
        handoff: &StoredHandoff,
        registration: &NodeRegistration,
    ) -> Result<(), ControllerError> {
        let prepared = handoff
            .prepared
            .as_ref()
            .ok_or_else(|| ControllerError::HandoffNotFound(handoff.id.clone()))?;
        self.validate_handoff_sources(handoff).await?;

        let current = self.nodes.read().await.clone();
        let mut source_updates = Vec::with_capacity(handoff.sources.len());
        for (source_id, names) in &handoff.sources {
            let mut source = current
                .get(source_id)
                .cloned()
                .ok_or_else(|| ControllerError::HandoffOwnershipChanged(source_id.clone()))?;
            for name in names {
                if source.registration.hostnames.contains(name) {
                    source.released_hostnames.insert(name.clone());
                } else if !source.released_hostnames.contains(name) {
                    return Err(ControllerError::HandoffOwnershipChanged(name.clone()));
                }
            }
            source_updates.push((source_id.clone(), source));
        }
        let target = StoredNode {
            registration: registration.clone(),
            certificate: prepared.certificate.clone(),
            renewal: prepared.renewal.clone(),
            released_hostnames: BTreeSet::new(),
        };

        self.persist_node(&target).await?;
        for (_, source) in &source_updates {
            self.persist_node(source).await?;
        }
        {
            let mut nodes = self.nodes.write().await;
            nodes.insert(registration.node_id.clone(), target.clone());
            for (source_id, source) in source_updates {
                nodes.insert(source_id, source);
            }
        }
        self.telemetry.node_state(
            &registration.node_id,
            target.certificate.generation,
            target.renewal.as_ref().map(|schedule| schedule.renew_after),
            target
                .renewal
                .as_ref()
                .and_then(|schedule| schedule.ari_check_after),
        );

        for name in &registration.hostnames {
            self.cloudflare
                .ensure_a(name, registration.tailscale_ip)
                .await?;
        }
        self.delete_handoff(&handoff.id).await?;
        self.handoffs.write().await.remove(&handoff.id);
        info!(
            offer_id = %handoff.id,
            target_node_id = %registration.node_id,
            names = handoff.moved_hostnames().len(),
            "committed hostname handoff"
        );
        Ok(())
    }

    async fn persist_handoff(&self, handoff: &StoredHandoff) -> Result<(), ControllerError> {
        let path = self.handoff_path(&handoff.id);
        durable_replace(&path, &serde_json::to_vec_pretty(handoff)?).await?;
        Ok(())
    }

    async fn delete_handoff(&self, id: &str) -> Result<(), ControllerError> {
        let path = self.handoff_path(id);
        match fs::remove_file(path).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn handoff_path(&self, id: &str) -> PathBuf {
        self.handoffs_dir.join(format!("{id}.json"))
    }

    async fn prune_expired_handoffs(&self) -> Result<(), ControllerError> {
        let now = unix_now();
        let expired = self
            .handoffs
            .read()
            .await
            .iter()
            .filter_map(|(id, handoff)| handoff.expired(now).then_some(id.clone()))
            .collect::<Vec<_>>();
        for id in &expired {
            self.delete_handoff(id).await?;
        }
        if !expired.is_empty() {
            let mut handoffs = self.handoffs.write().await;
            for id in expired {
                handoffs.remove(&id);
            }
        }
        Ok(())
    }
}

fn conflicting_ready_handoff(
    handoffs: &BTreeMap<String, StoredHandoff>,
    candidate: &StoredHandoff,
    now: i64,
) -> Option<(String, String)> {
    let candidate_names = candidate
        .target
        .hostnames
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    handoffs.values().find_map(|existing| {
        if existing.id == candidate.id || existing.expired(now) || !existing.ready() {
            return None;
        }
        existing
            .target
            .hostnames
            .iter()
            .find(|name| candidate_names.contains(*name))
            .cloned()
            .map(|name| (name, existing.target.node_id.clone()))
    })
}

fn handoff_target_matches(
    handoff: &StoredHandoff,
    registration: &NodeRegistration,
) -> Result<bool, IdentityError> {
    Ok(handoff.target.node_id == registration.node_id
        && handoff.target.tailscale_ip == registration.tailscale_ip
        && handoff.target.hostnames == registration.hostnames
        && same_csr_public_key(&handoff.target.csr_pem, &registration.csr_pem)?)
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, net::IpAddr};

    use certifex_core::NodeIdentity;

    use super::*;

    fn registration(
        identity: &NodeIdentity,
        node_id: &str,
        names: &[&str],
    ) -> Result<NodeRegistration, IdentityError> {
        let hostnames = names
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>();
        Ok(NodeRegistration {
            node_id: node_id.to_owned(),
            tailscale_ip: IpAddr::from([100, 64, 0, 9]),
            csr_pem: identity.csr_pem(&hostnames)?,
            hostnames,
            installed_generation: None,
        })
    }

    #[test]
    fn target_match_is_bound_to_key_and_names() -> Result<(), Box<dyn std::error::Error>> {
        let identity = NodeIdentity::generate()?;
        let other = NodeIdentity::generate()?;
        let target = registration(&identity, "new", &["svc.example.com"])?;
        let handoff = StoredHandoff {
            id: "offer".to_owned(),
            target: target.clone(),
            sources: BTreeMap::from([("old".to_owned(), vec!["svc.example.com".to_owned()])]),
            approvals: BTreeSet::new(),
            prepared: None,
            committing: false,
            updated_at: 1,
        };

        assert!(handoff_target_matches(&handoff, &target)?);
        assert!(!handoff_target_matches(
            &handoff,
            &registration(&other, "new", &["svc.example.com"])?
        )?);
        assert!(!handoff_target_matches(
            &handoff,
            &registration(&identity, "new", &["other.example.com"])?
        )?);
        Ok(())
    }

    #[test]
    fn all_source_owners_must_approve() -> Result<(), Box<dyn std::error::Error>> {
        let identity = NodeIdentity::generate()?;
        let mut handoff = StoredHandoff {
            id: "offer".to_owned(),
            target: registration(&identity, "new", &["one.example.com", "two.example.com"])?,
            sources: BTreeMap::from([
                ("old-a".to_owned(), vec!["one.example.com".to_owned()]),
                ("old-b".to_owned(), vec!["two.example.com".to_owned()]),
            ]),
            approvals: BTreeSet::new(),
            prepared: None,
            committing: false,
            updated_at: 1,
        };
        assert!(!handoff.ready());
        handoff.approvals.insert("old-a".to_owned());
        assert!(!handoff.ready());
        handoff.approvals.insert("old-b".to_owned());
        assert!(handoff.ready());
        Ok(())
    }

    #[test]
    fn ready_handoff_reserves_entire_target_hostname_set() -> Result<(), Box<dyn std::error::Error>>
    {
        let identity_a = NodeIdentity::generate()?;
        let identity_b = NodeIdentity::generate()?;
        let mut first = StoredHandoff {
            id: "first".to_owned(),
            target: registration(
                &identity_a,
                "new-a",
                &["moved-a.example.com", "free.example.com"],
            )?,
            sources: BTreeMap::from([("old-a".to_owned(), vec!["moved-a.example.com".to_owned()])]),
            approvals: BTreeSet::from(["old-a".to_owned()]),
            prepared: None,
            committing: false,
            updated_at: 1,
        };
        let mut second = StoredHandoff {
            id: "second".to_owned(),
            target: registration(
                &identity_b,
                "new-b",
                &["moved-b.example.com", "free.example.com"],
            )?,
            sources: BTreeMap::from([("old-b".to_owned(), vec!["moved-b.example.com".to_owned()])]),
            approvals: BTreeSet::from(["old-b".to_owned()]),
            prepared: None,
            committing: false,
            updated_at: 1,
        };
        assert!(first.ready());
        assert!(second.ready());
        let handoffs = BTreeMap::from([(first.id.clone(), first.clone())]);
        assert_eq!(
            conflicting_ready_handoff(&handoffs, &second, 1),
            Some(("free.example.com".to_owned(), "new-a".to_owned()))
        );
        assert_eq!(
            conflicting_ready_handoff(&handoffs, &second, HANDOFF_OFFER_TTL_SECONDS + 2),
            None
        );
        first.approvals.clear();
        second.approvals.clear();
        let handoffs = BTreeMap::from([(first.id.clone(), first)]);
        assert_eq!(conflicting_ready_handoff(&handoffs, &second, 1), None);
        Ok(())
    }

    #[test]
    fn offers_expire_after_inactivity_even_when_approved() -> Result<(), Box<dyn std::error::Error>>
    {
        let identity = NodeIdentity::generate()?;
        let mut handoff = StoredHandoff {
            id: "offer".to_owned(),
            target: registration(&identity, "new", &["svc.example.com"])?,
            sources: BTreeMap::from([("old".to_owned(), vec!["svc.example.com".to_owned()])]),
            approvals: BTreeSet::new(),
            prepared: None,
            committing: false,
            updated_at: 1,
        };
        handoff.approvals.insert("old".to_owned());
        assert!(!handoff.expired(HANDOFF_OFFER_TTL_SECONDS));
        assert!(handoff.expired(HANDOFF_OFFER_TTL_SECONDS + 2));
        handoff.updated_at = HANDOFF_OFFER_TTL_SECONDS;
        assert!(!handoff.expired(HANDOFF_OFFER_TTL_SECONDS * 2));
        handoff.committing = true;
        assert!(!handoff.expired(i64::MAX));
        Ok(())
    }
}
