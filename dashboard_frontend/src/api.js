export async function fetchJobs() {
  const response = await fetch("/api/jobs");
  if (!response.ok) {
    throw new Error("Unable to load jobs");
  }
  return response.json();
}

export async function fetchNotifications() {
  const response = await fetch("/api/notifications");
  if (!response.ok) {
    throw new Error("Unable to load notifications");
  }
  return response.json();
}
