//! Memory analysis session management.

use crate::memory::image::MemoryImage;
use crate::memory::virtual_memory::VirtualMemory;
use isf::IsfSymbols;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// A single memory analysis session.
#[allow(dead_code)]
pub struct MemorySession {
    /// Unique session ID.
    pub id: String,
    /// Path to the memory dump file.
    pub image_path: String,
    /// The memory-mapped image.
    pub image: MemoryImage,
    /// Parsed ISF symbols (if available).
    pub symbols: Option<Arc<IsfSymbols>>,
    /// Detected profile name (e.g., "Win10x64_19041").
    pub profile: Option<String>,
    /// Directory Table Base for kernel virtual memory.
    pub dtb: Option<u64>,
    /// Kernel base address for symbol relocation.
    pub kernel_base: Option<u64>,
    /// PsActiveProcessHead virtual address (from KDBG).
    pub ps_active_process_head: Option<u64>,
    /// Windows build number (best-effort).
    pub windows_build: Option<u32>,
    /// Virtual memory layer (created when DTB + physical layer are available).
    pub virtual_memory: Option<Arc<VirtualMemory>>,
    /// Creation timestamp.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Cached plugin results.
    pub cache: HashMap<String, serde_json::Value>,
}

impl MemorySession {
    pub fn new(id: String, image_path: String, image: MemoryImage) -> Self {
        MemorySession {
            id,
            image_path,
            image,
            symbols: None,
            profile: None,
            dtb: None,
            kernel_base: None,
            ps_active_process_head: None,
            windows_build: None,
            virtual_memory: None,
            created_at: chrono::Utc::now(),
            cache: HashMap::new(),
        }
    }

    pub fn image_size(&self) -> u64 {
        self.image.size()
    }

    /// Initialize virtual memory translation from DTB.
    /// Must be called after DTB is set.
    pub fn init_virtual_memory(&mut self) -> Result<(), String> {
        let dtb = self.dtb.ok_or("No DTB set")?;
        let physical = self.image.physical_layer();
        let vm = VirtualMemory::with_dtb(physical, dtb)?;
        self.virtual_memory = Some(Arc::new(vm));
        Ok(())
    }
}

/// Global session store.
#[derive(Clone)]
pub struct SessionStore {
    sessions: Arc<RwLock<HashMap<String, Arc<RwLock<MemorySession>>>>>,
}

impl SessionStore {
    pub fn new() -> Self {
        SessionStore {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a new session and return its ID.
    pub async fn create_session(&self, image_path: String, image: MemoryImage) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let session = MemorySession::new(id.clone(), image_path, image);
        let mut sessions = self.sessions.write().await;
        sessions.insert(id.clone(), Arc::new(RwLock::new(session)));
        id
    }

    /// Get a session by ID.
    pub async fn get_session(&self, id: &str) -> Option<Arc<RwLock<MemorySession>>> {
        let sessions = self.sessions.read().await;
        sessions.get(id).cloned()
    }

    /// List all sessions.
    pub async fn list_sessions(&self) -> Vec<(String, String, u64, Option<String>, String)> {
        let sessions = self.sessions.read().await;
        let mut result = Vec::new();
        for (id, session_lock) in sessions.iter() {
            let session = session_lock.read().await;
            result.push((
                id.clone(),
                session.image_path.clone(),
                session.image_size(),
                session.profile.clone(),
                session.created_at.to_rfc3339(),
            ));
        }
        result
    }

    /// Remove a session.
    #[allow(dead_code)]
    pub async fn remove_session(&self, id: &str) -> bool {
        let mut sessions = self.sessions.write().await;
        sessions.remove(id).is_some()
    }

    /// Count active sessions.
    pub async fn count(&self) -> usize {
        let sessions = self.sessions.read().await;
        sessions.len()
    }
}
