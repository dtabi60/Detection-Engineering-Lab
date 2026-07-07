import { apiGet, apiPost } from "./client";

export function getAlerts() {
  return apiGet("/api/v1/alerts/");
}

export function getCase(caseId) {
  return apiGet(`/api/v1/cases/${caseId}`);
}

export function getInvestigation(alertId) {
  return apiGet(`/api/v1/alerts/${alertId}`);
}

export function getStoryline(storylineId) {
  return apiGet(`/api/v1/storylines/${storylineId}`);
}

export function getProcessTree(processGuid) {
  return apiGet(`/api/v1/process-tree/${processGuid}`);
}

export function getResponseActions(alertId) {
  return apiGet(`/api/v1/response-actions/${alertId}`);
}

export function createResponseAction(payload) {
  return apiPost("/api/v1/response-actions/", payload);
}