import React, { useState, useEffect, useRef } from 'react';
import { encryptArrayBuffer } from './services/crypto.js';
import { getClientConfig } from './services/clientConfig.js';
import { listFiles, createFile, deleteFile as deleteFileApi, patchFile, addActivity, listActivity, mongoStatus, registerUser, loginUser, setAuthToken } from './services/mongoApi.js';
import { loadAuthMeta, storeAuthMeta, clearAuthMeta, decryptWrappedDEK } from './services/auth.js';

const App = () => {
  // State management
  const [darkMode, setDarkMode] = useState(false);
  const [currentView, setCurrentView] = useState('dashboard');
  const [showNotification, setShowNotification] = useState(false);
  const [notification, setNotification] = useState({ message: '', type: 'success' });
  const [uploadedFiles, setUploadedFiles] = useState([]);
  const [loadingFiles, setLoadingFiles] = useState(false);
  const [folders] = useState([
    { name: 'Personal ID', count: 12, color: 'text-blue-500', bgColor: 'bg-blue-100' },
    { name: 'Financial', count: 8, color: 'text-green-500', bgColor: 'bg-green-100' },
    { name: 'Medical', count: 15, color: 'text-red-500', bgColor: 'bg-red-100' },
    { name: 'Legal', count: 5, color: 'text-purple-500', bgColor: 'bg-purple-100' },
    { name: 'Education', count: 7, color: 'text-orange-500', bgColor: 'bg-orange-100' },
    { name: 'Other', count: 3, color: 'text-gray-500', bgColor: 'bg-gray-100' }
  ]);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('all');
  const [isDragging, setIsDragging] = useState(false);
  const [user] = useState({ name: 'John Doe', email: 'john@example.com' });
  const [securityStatus] = useState({ twoFactor: true, encryption: true, lastLogin: 'Today, 10:30 AM' });
  const [trustedContacts] = useState([
    { id: 1, name: 'Jane Smith', email: 'jane@example.com', relationship: 'Spouse', accessLevel: 'Emergency' },
    { id: 2, name: 'Robert Johnson', email: 'robert@example.com', relationship: 'Brother', accessLevel: 'View Only' },
    { id: 3, name: 'Sarah Wilson', email: 'sarah@example.com', relationship: 'Attorney', accessLevel: 'Full Access' }
  ]);

  const fileInputRef = useRef(null);
  const legacyReuploadInputRef = useRef(null);

  // Auth state for unified server-first authentication
  const [authState, setAuthState] = useState({ 
    unlocked: false, 
    mode: 'login', // 'login' | 'register'
    stage: 'form', // 'form' | 'showRecovery' 
    working: false, 
    error: '' 
  });
  const [authForm, setAuthForm] = useState({
    email: '',
    phone: '',
    password: '',
    passwordConfirm: ''
  });
  const [recoveryKey, setRecoveryKey] = useState('');
  const [contentKey, setContentKey] = useState(null);
  const [persistedLoaded, setPersistedLoaded] = useState(false);

  // User profile and settings state
  const [userProfile, setUserProfile] = useState(()=>{ try { return JSON.parse(localStorage.getItem('sv_profile')) || { name: user.name, email: user.email }; } catch { return { name: user.name, email: user.email }; }});
  const [settingsState, setSettingsState] = useState(()=>{ try { return JSON.parse(localStorage.getItem('sv_settings')) || { twoFactor: true, emailNotif: true, pushNotif: true, accessAlerts: true, cloudBackup: true }; } catch { return { twoFactor: true, emailNotif: true, pushNotif: true, accessAlerts: true, cloudBackup: true }; }});
  const [contacts, setContacts] = useState(()=>{ try { return JSON.parse(localStorage.getItem('sv_contacts')) || trustedContacts; } catch { return trustedContacts; }});
  const [showContactModal, setShowContactModal] = useState(false);
  const [contactForm, setContactForm] = useState({ name:'', email:'', relationship:'Friend', accessLevel:'View Only' });
  const [oneTimeLinks, setOneTimeLinks] = useState(()=>{ try { return JSON.parse(localStorage.getItem('sv_links')) || []; } catch { return []; }});
  // Legacy linkGenState replaced by linkForm for UI binding
  const [linkForm, setLinkForm] = useState({ fileId:'', expiry:'7d', working:false, error:'' });
  const [emergencyConfig, setEmergencyConfig] = useState(()=>{ try { return JSON.parse(localStorage.getItem('sv_emergency')) || { waitingPeriod:'30 days', enabled:false }; } catch { return { waitingPeriod:'30 days', enabled:false }; }});
  const [showPasswordModal, setShowPasswordModal] = useState(false);
  const [pwdForm, setPwdForm] = useState({ current:'', next:'', confirm:'', working:false, error:'' });
  // Upload progress (per temporary id)
  const [uploadProgress, setUploadProgress] = useState({});
  // Cloud/backend integration (Mongo replacement for previous Firebase logic)
  const [authProviderLoading] = useState(false); // placeholder (Google sign-in removed)
  const [failedUploads, setFailedUploads] = useState({}); // { fileId: { buffer, mime, name, category, size } }
  const [offlineMode, setOfflineMode] = useState(false); // manual toggle
  const [activityLog, setActivityLog] = useState([]); // activity entries from Mongo
  const [mongoConnected, setMongoConnected] = useState(null); // null=unknown, bool once fetched
  const [legacyReuploadTarget, setLegacyReuploadTarget] = useState(null);
  const [cloudinaryErrors, setCloudinaryErrors] = useState({}); // { fileId: message }
  const [lastCloudinaryError, setLastCloudinaryError] = useState(null);
  const [showUserMenu, setShowUserMenu] = useState(false); // For header user dropdown
  // Helper to log an activity entry (Mongo)
  const logActivity = async (entry) => {
    try {
      if (offlineMode) return;
      const email = userProfile.email || user.email;
      await addActivity({ email, ts: Date.now(), ...entry });
      setActivityLog(prev => [{ email, ts: Date.now(), ...entry }, ...prev].slice(0,25));
    } catch {/* ignore */}
  };

  const handleGoogleSignIn = async () => {
    // Deprecated (Firebase removed); keep placeholder to avoid UI errors if invoked.
    showNotificationMessage('Federated sign-in not implemented (Firebase removed)','warning');
  };

  // Apply dark mode
  useEffect(() => {
    if (darkMode) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, [darkMode]);

  // Show notification
  const showNotificationMessage = (message, type = 'success') => {
    setNotification({ message, type });
    setShowNotification(true);
    setTimeout(() => {
      setShowNotification(false);
    }, 5000);
  };

  // Load persisted encrypted metadata
  useEffect(() => {
    if (!authState.unlocked) return;
    try {
      const raw = localStorage.getItem('sv_files');
      if (raw) {
        const parsed = JSON.parse(raw);
        setUploadedFiles(parsed);
      }
    } catch (e) { /* ignore */ }
    setPersistedLoaded(true);
  }, [authState.unlocked]);

  // Persist on change
  useEffect(() => {
    if (!authState.unlocked) return;
    localStorage.setItem('sv_files', JSON.stringify(uploadedFiles));
  }, [uploadedFiles, authState.unlocked]);

  useEffect(() => {
    // Check for existing auth metadata on load
    const authMeta = loadAuthMeta();
    if (authMeta && authMeta.email) {
      // User has auth metadata, show login with email prefilled
      setAuthForm(f => ({ ...f, email: authMeta.email }));
      setAuthState(a => ({ ...a, mode: 'login' }));
    } else {
      // No auth metadata, show register form
      setAuthState(a => ({ ...a, mode: 'register' }));
    }
  }, []);
  
  // Close user menu when clicking outside
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (showUserMenu && !event.target.closest('#user-menu-button') && !event.target.closest('.absolute')) {
        setShowUserMenu(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [showUserMenu]);
  
  // Mongo status + initial loads when unlocked
  // Initial Mongo status + retry until connected (handles race where server connects after first check)
  useEffect(()=>{
    let attempts = 0;
    let stopped = false;
    const maxAttempts = 12; // ~24s total (2s interval)
    const check = async () => {
      if (stopped) return;
      try {
        const st = await mongoStatus();
        setMongoConnected(!!st.connected);
        if (!st.connected && attempts < maxAttempts) {
          attempts++; setTimeout(check, 2000);
        }
      } catch {
        setMongoConnected(false);
        if (attempts < maxAttempts) { attempts++; setTimeout(check, 2500); }
      }
    };
    check();
    return () => { stopped = true; };
  }, []);
  useEffect(()=>{
    if (!authState.unlocked || offlineMode) return;
    loadRemoteFiles();
  }, [authState.unlocked, offlineMode]);
  useEffect(()=>{
    if (!authState.unlocked || offlineMode) return;
    let stop = false;
    const fetchAct = async () => {
      try { const email = userProfile.email || user.email; const r = await listActivity(email, 25); if(!stop) setActivityLog(r.activity||[]); } catch {}
    };
    fetchAct();
    const iv = setInterval(fetchAct, 10000);
    return ()=>{ stop=true; clearInterval(iv); };
  }, [authState.unlocked, offlineMode, userProfile.email]);

  const loadRemoteFiles = async () => {
    if (offlineMode) return;
    setLoadingFiles(true);
    try {
      const email = userProfile.email || user.email;
      const r = await listFiles(email);
      const files = (r.files||[]).map(doc => ({
        ...doc,
        id: doc._id || doc.id,
        docId: doc._id || doc.id,
        uid: email
      }));
      setUploadedFiles(prev => {
        // Merge: keep local items not yet uploaded (no docId)
        const locals = prev.filter(f => !f.docId);
        return [...files, ...locals];
      });
    } catch(e){ console.warn('Mongo list failed', e); }
    setLoadingFiles(false);
  };

  const handleRegister = async () => {
    const { email, phone, password, passwordConfirm } = authForm;
    if (!email || !phone || !password) {
      setAuthState(a => ({ ...a, error: 'Please fill all fields' }));
      return;
    }
    if (password.length < 8) {
      setAuthState(a => ({ ...a, error: 'Password must be at least 8 characters' }));
      return;
    }
    if (password !== passwordConfirm) {
      setAuthState(a => ({ ...a, error: 'Passwords do not match' }));
      return;
    }
    
    try {
      setAuthState(a => ({ ...a, working: true, error: '' }));
      
      // Call register API
      const result = await registerUser({ email, phone, password });
      
      // Store auth metadata
      const authMeta = {
        email: email.toLowerCase(),
        kdfSalt: result.kdfSalt,
        kdfIterations: result.kdfIterations,
        wrappedDEK_pw: result.wrappedDEK_pw
      };
      storeAuthMeta(authMeta);
      
      // Store token
      setAuthToken(result.token);
      
      // Show recovery key
      setRecoveryKey(result.recoveryKey);
      setAuthState(a => ({ ...a, working: false, stage: 'showRecovery' }));
      
    } catch (e) {
      setAuthState(a => ({ ...a, working: false, error: e.message || 'Registration failed' }));
    }
  };

  const handleLogin = async () => {
    const { email, password } = authForm;
    if (!email || !password) {
      setAuthState(a => ({ ...a, error: 'Please enter email and password' }));
      return;
    }
    
    try {
      setAuthState(a => ({ ...a, working: true, error: '' }));
      
      // Call login API
      const result = await loginUser({ email, password });
      
      // Update auth metadata with latest from server
      const authMeta = {
        email: email.toLowerCase(),
        kdfSalt: result.kdfSalt,
        kdfIterations: result.kdfIterations,
        wrappedDEK_pw: result.wrappedDEK_pw
      };
      storeAuthMeta(authMeta);
      
      // Store token
      setAuthToken(result.token);
      
      // Decrypt and import DEK
      const dek = await decryptWrappedDEK({
        password,
        wrapped: result.wrappedDEK_pw,
        kdfSalt: result.kdfSalt,
        kdfIterations: result.kdfIterations
      });
      
      setContentKey(dek);
      setAuthState({ unlocked: true, mode: 'login', stage: 'form', working: false, error: '' });
      showNotificationMessage('Logged in successfully', 'success');
      
    } catch (e) {
      setAuthState(a => ({ ...a, working: false, error: e.message || 'Login failed' }));
    }
  };

  const handleRecoveryConfirm = async () => {
    // User confirmed they saved recovery key, now unlock vault
    try {
      const authMeta = loadAuthMeta();
      if (!authMeta) throw new Error('Auth metadata missing');
      
      const dek = await decryptWrappedDEK({
        password: authForm.password,
        wrapped: authMeta.wrappedDEK_pw,
        kdfSalt: authMeta.kdfSalt,
        kdfIterations: authMeta.kdfIterations
      });
      
      setContentKey(dek);
      setAuthState({ unlocked: true, mode: 'register', stage: 'form', working: false, error: '' });
      setRecoveryKey(''); // Clear recovery key from memory
      showNotificationMessage('Account created and vault unlocked!', 'success');
      
    } catch (e) {
      setAuthState(a => ({ ...a, error: e.message || 'Failed to unlock vault' }));
    }
  };

  const handleLock = () => {
    setContentKey(null);
    setAuthState(a => ({ ...a, unlocked: false }));
    showNotificationMessage('Vault locked', 'success');
  };

  const handleLogout = () => {
    setContentKey(null);
    clearAuthMeta();
    setAuthToken(null);
    setAuthForm({ email: '', phone: '', password: '', passwordConfirm: '' });
    setAuthState({ unlocked: false, mode: 'login', stage: 'form', working: false, error: '' });
    showNotificationMessage('Logged out', 'success');
  };

  // Format file size
  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  // Get file type icon
  const getFileType = (filename) => {
    const ext = filename.split('.').pop().toLowerCase();
    if (['jpg', 'jpeg', 'png', 'gif', 'bmp'].includes(ext)) return 'image';
    if (['pdf'].includes(ext)) return 'pdf';
    if (['doc', 'docx', 'txt'].includes(ext)) return 'doc';
    if (['xls', 'xlsx'].includes(ext)) return 'spreadsheet';
    return 'file';
  };

  // Get file icon
  const getFileIcon = (type) => {
    switch (type) {
      case 'pdf': return <i className="fas fa-file-pdf text-red-600"></i>;
      case 'image': return <i className="fas fa-file-image text-green-600"></i>;
      case 'doc': return <i className="fas fa-file-word text-blue-600"></i>;
      case 'spreadsheet': return <i className="fas fa-file-excel text-green-600"></i>;
      default: return <i className="fas fa-file text-gray-600"></i>;
    }
  };

  // Handle drag and drop
  const handleDragEnter = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (!isDragging) setIsDragging(true);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
    
    const files = e.dataTransfer.files;
    if (files && files.length > 0) {
      handleFileUpload(files);
    }
  };

  // Handle file input change
  const handleFileInputChange = (e) => {
    const files = e.target.files;
    if (files && files.length > 0) {
      handleFileUpload(files);
    }
    // Reset input
    e.target.value = null;
  };

  // Filtered files based on search and category
  const filteredFiles = uploadedFiles.filter(file => {
    const matchesSearch = file.name.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesCategory = selectedCategory === 'all' || file.category === selectedCategory;
    return matchesSearch && matchesCategory;
  });

  // Enhanced file upload with encryption placeholder (encrypt file bytes)
  const handleFileUpload = async (files) => {
    if (!contentKey) {
      showNotificationMessage('Unlock vault first', 'error');
      return;
    }
    const fileArray = Array.from(files);
    for (const file of fileArray) {
      try {
        // Create a temporary placeholder so user sees item immediately
        const tempId = 'temp-' + Date.now() + '-' + Math.random();
        const placeholder = {
          id: tempId,
          name: file.name,
            category: selectedCategory === 'all' ? 'Other' : selectedCategory,
          size: formatFileSize(file.size),
          date: new Date().toLocaleDateString(),
          type: getFileType(file.name),
          encrypted: false,
          uploading: true,
          rawBytes: file.size
        };
        setUploadedFiles(prev => [placeholder, ...prev]);
        const buf = await file.arrayBuffer();
  // Keep original buffer in case encryption/upload fails (not persisted, only memory)
  setFailedUploads(f => ({ ...f, [tempId]: { buffer: buf, mime: file.type || 'application/octet-stream', name: file.name, category: placeholder.category, size: file.size } }));
        const encrypted = await encryptArrayBuffer(contentKey, buf);
        // Upload encrypted data to Cloudinary (unsigned raw upload)
        let cloudinaryId = null;
        let cloudErrMsg = null;
        try {
          const { cloudName, uploadPreset: unsignedPreset } = await getClientConfig();
          if (cloudName && unsignedPreset) {
            const binary = atob(encrypted.data);
            const bytes = new Uint8Array(binary.length); for (let i=0;i<binary.length;i++) bytes[i]=binary.charCodeAt(i);
            const blob = new Blob([bytes], { type: file.type||'application/octet-stream' });
            const form = new FormData();
            form.append('file', blob);
            form.append('upload_preset', unsignedPreset);
            form.append('folder', 'vault');
            form.append('resource_type', 'raw');
            setUploadProgress(p => ({ ...p, [tempId]: 10 }));
            const apiBase = import.meta.env.VITE_API_BASE_URL || '';
            const cloudinaryUrl = apiBase
              ? `${apiBase}/api/cloudinary/upload` // If you proxy uploads through your backend
              : `https://api.cloudinary.com/v1_1/${cloudName}/raw/upload`;
            const res = await fetch(cloudinaryUrl, { method:'POST', body: form });
            if (!res.ok) {
              let errTxt = 'Cloudinary upload failed';
              try { const ej = await res.json(); if (ej.error && ej.error.message) errTxt = ej.error.message; } catch {}
              throw new Error(errTxt);
            }
            const json = await res.json();
            cloudinaryId = json.public_id;
            setUploadProgress(p => ({ ...p, [tempId]: 100 }));
          }
        } catch(e){ console.warn('Cloudinary upload error', e); cloudErrMsg = e.message || 'Cloudinary upload failed'; }
        const finalId = Date.now() + Math.random();
        const newFile = {
          id: finalId,
          localId: finalId,
          name: file.name,
          category: selectedCategory === 'all' ? 'Other' : selectedCategory,
          size: formatFileSize(file.size),
          date: new Date().toLocaleDateString(),
          type: getFileType(file.name),
          encrypted: true,
          iv: encrypted.iv,
          data: encrypted.data,
          mime: file.type || 'application/octet-stream',
          cloudinaryId,
          cloudError: cloudErrMsg || null,
          rawBytes: file.size,
          uid: userProfile.email || user.email,
          createdAt: Date.now(),
          uploading: false
        };
        setUploadedFiles(prev => prev.map(f => f.id === tempId ? newFile : f));
        if (cloudErrMsg) { setCloudinaryErrors(e => ({ ...e, [finalId]: cloudErrMsg })); setLastCloudinaryError(cloudErrMsg); }
        setUploadProgress(p => { const { [tempId]:_, ...rest } = p; return rest; });
        setFailedUploads(f => { const { [tempId]:__, ...rest } = f; return rest; });
        logActivity({ action:'upload', id:newFile.id, name:newFile.name, size:newFile.rawBytes, category:newFile.category });
        // Persist to Mongo
        try {
          const email = userProfile.email || user.email;
          const r = await createFile({ email, name:newFile.name, category:newFile.category, size:newFile.size, date:newFile.date, type:newFile.type, iv:newFile.iv, data:newFile.data, mime:newFile.mime, cloudinaryId:newFile.cloudinaryId, rawBytes:newFile.rawBytes, createdAt:newFile.createdAt });
          if (r && r.id) setUploadedFiles(prev => prev.map(f => f.id === newFile.id ? { ...f, docId: r.id, id: r.id } : f));
        } catch(e){ console.warn('Mongo create failed', e); }
      } catch (e) {
  // Mark placeholder (if still present) as failed so UI doesn't stay stuck
  setUploadedFiles(prev => prev.map(f => f.name === file.name && f.uploading ? { ...f, uploading:false, error:'Encrypt failed'} : f));
  showNotificationMessage('Error encrypting ' + file.name, 'error');
      }
    }
    showNotificationMessage(`Encrypted & stored ${fileArray.length} file(s)`, 'success');
  };

  const retryFailedUpload = async (file) => {
    if (!contentKey) { showNotificationMessage('Unlock vault first', 'error'); return; }
    const failMeta = failedUploads[file.id];
    if (!failMeta) { showNotificationMessage('Original data not available; re-upload', 'error'); return; }
    // Set uploading state
    setUploadedFiles(prev => prev.map(f => f.id === file.id ? { ...f, uploading:true, error:undefined } : f));
    try {
      const encrypted = await encryptArrayBuffer(contentKey, failMeta.buffer);
      let cloudinaryId = null;
      let cloudErrMsg = null;
      try {
        const { cloudName, uploadPreset: unsignedPreset } = await getClientConfig();
        if (cloudName && unsignedPreset) {
          const binary = atob(encrypted.data);
          const bytes = new Uint8Array(binary.length); for (let i=0;i<binary.length;i++) bytes[i]=binary.charCodeAt(i);
          const blob = new Blob([bytes], { type: failMeta.mime });
          const form = new FormData();
            form.append('file', blob);
            form.append('upload_preset', unsignedPreset);
            form.append('folder', 'vault');
            form.append('resource_type', 'raw');
          setUploadProgress(p => ({ ...p, [file.id]: 10 }));
          const res = await fetch(`https://api.cloudinary.com/v1_1/${cloudName}/raw/upload`, { method:'POST', body: form });
          if (!res.ok) {
            let errTxt = 'Cloudinary retry upload failed';
            try { const ej = await res.json(); if (ej.error && ej.error.message) errTxt = ej.error.message; } catch {}
            throw new Error(errTxt);
          }
          const json = await res.json();
          cloudinaryId = json.public_id;
          setUploadProgress(p => ({ ...p, [file.id]: 100 }));
        }
      } catch(e){ console.warn('Retry Cloudinary upload failed', e); cloudErrMsg = e.message || 'Cloudinary retry upload failed'; }
      const finalId = Date.now() + Math.random();
      const updated = {
        id: finalId,
        localId: finalId,
        name: failMeta.name,
        category: failMeta.category,
        size: formatFileSize(failMeta.size),
        date: new Date().toLocaleDateString(),
        type: getFileType(failMeta.name),
        encrypted: true,
        iv: encrypted.iv,
        data: encrypted.data,
        mime: failMeta.mime,
  cloudinaryId,
        cloudError: cloudErrMsg || null,
        rawBytes: failMeta.size,
  uid: userProfile.email || user.email,
        createdAt: Date.now(),
        uploading:false
      };
      setUploadedFiles(prev => prev.map(f => f.id === file.id ? updated : f));
      if (cloudErrMsg) { setCloudinaryErrors(e => ({ ...e, [finalId]: cloudErrMsg })); setLastCloudinaryError(cloudErrMsg); }
      setUploadProgress(p => { const { [file.id]:_, ...rest } = p; return rest; });
      setFailedUploads(f => { const { [file.id]:__, ...rest } = f; return rest; });
      try {
        const email = userProfile.email || user.email;
        const r = await createFile({ email, name:updated.name, category:updated.category, size:updated.size, date:updated.date, type:updated.type, iv:updated.iv, data:updated.data, mime:updated.mime, cloudinaryId:updated.cloudinaryId, rawBytes:updated.rawBytes, createdAt:updated.createdAt });
        if (r && r.id) setUploadedFiles(prev => prev.map(f => f.id === updated.id ? { ...f, docId: r.id, id:r.id } : f));
      } catch(e){ console.warn('Retry Mongo create failed', e); }
      showNotificationMessage('Retry succeeded', 'success');
  logActivity({ action:'retry-success', id:updated.id, name:updated.name, size:updated.rawBytes, category:updated.category });
    } catch(e){
      setUploadedFiles(prev => prev.map(f => f.id === file.id ? { ...f, uploading:false, error:'Retry failed'} : f));
      showNotificationMessage('Retry failed', 'error');
    }
  };

  // Choose a replacement file for legacy (needsReencrypt) entry
  const chooseLegacyReupload = (file) => {
    if (!contentKey) { showNotificationMessage('Unlock vault first','error'); return; }
    setLegacyReuploadTarget(file.id);
    if (legacyReuploadInputRef.current) legacyReuploadInputRef.current.value = '';
    legacyReuploadInputRef.current?.click();
  };

  const handleLegacyReuploadChange = async (e) => {
    const f = e.target.files && e.target.files[0];
    if (!f || !legacyReuploadTarget) return;
    if (!contentKey) { showNotificationMessage('Unlock vault first','error'); return; }
    const targetId = legacyReuploadTarget;
    setLegacyReuploadTarget(null);
    try {
      const buf = await f.arrayBuffer();
      const encrypted = await encryptArrayBuffer(contentKey, buf);
      // Optional Cloudinary upload for legacy replacement
      let cloudinaryId = null;
      try {
        const { cloudName, uploadPreset: unsignedPreset } = await getClientConfig();
        if (cloudName && unsignedPreset) {
          const binary = atob(encrypted.data);
          const bytes = new Uint8Array(binary.length); for (let i=0;i<binary.length;i++) bytes[i]=binary.charCodeAt(i);
          const blob = new Blob([bytes], { type: f.type || 'application/octet-stream' });
          const form = new FormData();
          form.append('file', blob);
          form.append('upload_preset', unsignedPreset);
          form.append('folder', 'vault');
          form.append('resource_type', 'raw');
          const res = await fetch(`https://api.cloudinary.com/v1_1/${cloudName}/raw/upload`, { method:'POST', body: form });
          if (res.ok) { const js = await res.json(); cloudinaryId = js.public_id; }
        }
      } catch(ex){ console.warn('Cloudinary legacy replace upload failed', ex); }
      const updated = {
        name: f.name,
        size: formatFileSize(f.size),
        rawBytes: f.size,
        date: new Date().toLocaleDateString(),
        iv: encrypted.iv,
        data: encrypted.data,
        mime: f.type || 'application/octet-stream',
        type: getFileType(f.name),
        encrypted: true,
        needsReencrypt: false,
        uploading: false,
        createdAt: Date.now(),
  uid: userProfile.email || user.email,
        cloudinaryId,
        error: undefined
      };
      setUploadedFiles(prev => prev.map(file => file.id === targetId ? { ...file, ...updated } : file));
      // Persist legacy replacement to Mongo if not present
      const fileEntry = uploadedFiles.find(x => x.id === targetId);
      if (!offlineMode && fileEntry && !fileEntry.docId) {
        try {
          const email = userProfile.email || user.email;
          const r = await createFile({ email, name:updated.name, category:fileEntry.category||'Other', size:updated.size, date:updated.date, type:updated.type, iv:updated.iv, data:updated.data, mime:updated.mime, cloudinaryId:updated.cloudinaryId||fileEntry.cloudinaryId||null, rawBytes:updated.rawBytes, createdAt:updated.createdAt });
          if (r && r.id) setUploadedFiles(prev => prev.map(f2 => f2.id === targetId ? { ...f2, docId: r.id, id:r.id } : f2));
        } catch(err){ console.warn('Legacy replacement Mongo add failed', err); }
      }
      logActivity({ action:'legacy-reupload', id:targetId, name: updated.name, size: updated.rawBytes });
      showNotificationMessage('File replaced & encrypted','success');
    } catch(err){
      console.warn('Legacy reupload failed', err);
      showNotificationMessage('Replace failed','error');
    }
  };

  // Add actions to existing file row: download, delete (UI additions below)
  const deleteFile = async (id) => {
    let targetDocId = null;
    setUploadedFiles(prev => {
      const file = prev.find(f => f.id === id);
      if (file && file.docId) targetDocId = file.docId;
      return prev.filter(f => f.id !== id);
    });
    if (targetDocId) {
      try { await deleteFileApi(targetDocId); } catch(e){ console.warn('Mongo delete failed', e); }
    }
    showNotificationMessage('File removed', 'success');
  logActivity({ action:'delete', id, name:'', size:0 });
  };

  const downloadFile = async (file) => {
    if (!contentKey) { showNotificationMessage('Unlock vault', 'error'); return; }
    try {
      const { decryptToArrayBuffer } = await import('./services/crypto.js');
      const plainBuf = await decryptToArrayBuffer(contentKey, file.iv, file.data);
      const blob = new Blob([plainBuf], { type: file.mime });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = file.name; a.click();
      URL.revokeObjectURL(url);
  logActivity({ action:'download', id:file.id, name:file.name, size:file.rawBytes||0, category:file.category });
    } catch (e) {
      showNotificationMessage('Decrypt failed', 'error');
    }
  };
  // Backfill existing encrypted file to Cloudinary if it lacks cloudinaryId
  const backfillCloudinary = async (file) => {
    if (file.cloudinaryId || !file.data || !file.iv) return;
  const { cloudName, uploadPreset: unsignedPreset } = await getClientConfig();
    if (!cloudName || !unsignedPreset) { showNotificationMessage('Set Cloudinary env vars first','error'); return; }
    // Mark uploading for visual feedback
    setUploadedFiles(prev => prev.map(f => f.id === file.id ? { ...f, uploading:true } : f));
    try {
      // Decode base64 to bytes
      const binary = atob(file.data);
      const bytes = new Uint8Array(binary.length); for (let i=0;i<binary.length;i++) bytes[i] = binary.charCodeAt(i);
      const blob = new Blob([bytes], { type: file.mime || 'application/octet-stream' });
      const form = new FormData();
      form.append('file', blob);
      form.append('upload_preset', unsignedPreset);
      form.append('folder', 'vault');
      form.append('resource_type', 'raw');
      const res = await fetch(`https://api.cloudinary.com/v1_1/${cloudName}/raw/upload`, { method:'POST', body: form });
      if (!res.ok) throw new Error('Cloudinary upload failed');
      const json = await res.json();
      const cid = json.public_id;
      setUploadedFiles(prev => prev.map(f => f.id === file.id ? { ...f, cloudinaryId: cid, uploading:false } : f));
  // (Firebase removed) previously would persist cloudinaryId to Firestore
  if (file.docId) { try { await patchFile(file.docId, { cloudinaryId: cid }); } catch(e){ console.warn('Mongo patch failed', e); } }
      logActivity({ action:'cloudinary-backfill', id:file.id, name:file.name, size:file.rawBytes||0, category:file.category });
      showNotificationMessage('Uploaded encrypted blob to Cloudinary');
    } catch(e){
      console.warn('Cloudinary backfill failed', e);
      setUploadedFiles(prev => prev.map(f => f.id === file.id ? { ...f, uploading:false } : f));
      showNotificationMessage('Backfill failed','error');
    }
  };
  const previewFile = async (file) => {
    if (!contentKey) { showNotificationMessage('Unlock vault', 'error'); return; }
    try {
      const { decryptToArrayBuffer } = await import('./services/crypto.js');
      const plainBuf = await decryptToArrayBuffer(contentKey, file.iv, file.data);
      const blob = new Blob([plainBuf], { type: file.mime });
      const url = URL.createObjectURL(blob);
      window.open(url, '_blank');
      setTimeout(()=>URL.revokeObjectURL(url), 60000);
  logActivity({ action:'preview', id:file.id, name:file.name, size:file.rawBytes||0, category:file.category });
    } catch(e){ showNotificationMessage('Preview failed','error'); }
  };

  // Persist new states
  useEffect(()=>{ localStorage.setItem('sv_profile', JSON.stringify(userProfile)); }, [userProfile]);
  useEffect(()=>{ localStorage.setItem('sv_settings', JSON.stringify(settingsState)); }, [settingsState]);
  useEffect(()=>{ localStorage.setItem('sv_contacts', JSON.stringify(contacts)); }, [contacts]);
  useEffect(()=>{ localStorage.setItem('sv_links', JSON.stringify(oneTimeLinks)); }, [oneTimeLinks]);
  useEffect(()=>{ localStorage.setItem('sv_emergency', JSON.stringify(emergencyConfig)); }, [emergencyConfig]);

  // Backfill any locally existing files that never got uploaded to Mongo (no docId) once unlocked
  useEffect(()=>{
    if (offlineMode || !authState.unlocked) return;
    const email = userProfile.email || user.email;
    const pending = uploadedFiles.filter(f => !f.docId && f.iv && f.data);
    const invalid = uploadedFiles.filter(f => !f.docId && (!f.iv || !f.data) && !f.needsReencrypt);
    if (invalid.length) setUploadedFiles(prev => prev.map(f => (!f.docId && (!f.iv || !f.data) && !f.needsReencrypt)? { ...f, needsReencrypt:true } : f));
    if (!pending.length) return;
    (async()=>{
      for(const f of pending){
        try {
          const r = await createFile({ email, name:f.name, category:f.category, size:f.size, date:f.date, type:f.type, iv:f.iv, data:f.data, mime:f.mime, cloudinaryId:f.cloudinaryId||null, rawBytes:f.rawBytes, createdAt:f.createdAt||Date.now() });
          if (r && r.id) setUploadedFiles(prev => prev.map(x => x.id === f.id ? { ...x, docId:r.id, id:r.id } : x));
        } catch(e){ console.warn('Backfill Mongo add failed', e); }
      }
    })();
  }, [uploadedFiles, offlineMode, authState.unlocked, userProfile.email]);

  // Dynamic storage usage calculation
  const totalBytes = uploadedFiles.reduce((sum,f)=> sum + (f.rawBytes || 0), 0);
  const storageLimit = 10 * 1024 * 1024 * 1024; // 10 GB
  const usedPercent = storageLimit ? Math.min(100, (totalBytes / storageLimit) * 100) : 0;

  // Modify file creation to include rawBytes (patch existing newFile creation)
  // ...existing code...

  // Handlers
  const toggleSetting = key => setSettingsState(s => ({ ...s, [key]: !s[key] }));

  const saveProfile = (name, email) => { setUserProfile({ name, email }); showNotificationMessage('Profile updated'); };

  const addContact = () => {
    if (!contactForm.name || !contactForm.email) return;
    setContacts(prev => [{ id: Date.now(), ...contactForm }, ...prev]);
    setShowContactModal(false);
    setContactForm({ name:'', email:'', relationship:'Friend', accessLevel:'View Only' });
    showNotificationMessage('Contact added');
  };
  const removeContact = id => { setContacts(prev=> prev.filter(c=>c.id!==id)); showNotificationMessage('Contact removed'); };

  const generateLink = () => {
    if (!linkForm.fileId) { setLinkForm(s=>({...s, error:'Select a document'})); return; }
    const file = uploadedFiles.find(f=> String(f.id) === String(linkForm.fileId));
    if (!file) { setLinkForm(s=>({...s, error:'File not found'})); return; }
    const now = Date.now();
    const expiryMap = { '7d': 7*864e5, '1d': 864e5, '1h': 3600e3, '30m': 1800e3 };
    const ms = expiryMap[linkForm.expiry] || 7*864e5;
    const token = crypto.randomUUID();
    const linkObj = { id: token, fileId: file.id, filename: file.name, createdAt: now, expiresAt: now + ms, accessUrl: `${window.location.origin}/share/${token}` };
    setOneTimeLinks(prev=>[linkObj, ...prev]);
    setLinkForm(s=>({ ...s, fileId:'', error:'', working:false }));
    showNotificationMessage('Secure link generated');
  };
  const revokeLink = id => { setOneTimeLinks(prev=> prev.filter(l=>l.id!==id)); showNotificationMessage('Link revoked'); };

  const enableEmergency = () => { setEmergencyConfig(c=> ({ ...c, enabled:true })); showNotificationMessage('Emergency access enabled'); };

  const changeMasterPassword = async () => {
    // TODO: Implement server-side password change via /api/change-password
    setPwdForm(f=>({...f, error:'Password change not implemented in unified auth mode'}));
    return;
    
    // Legacy implementation disabled for unified auth
    /*
    if (!contentKey) { setPwdForm(f=>({...f, error:'Unlock first'})); return; }
  if (import.meta.env.VITE_LOCK_MASTER_PASSWORD === 'true') { setPwdForm(f=>({...f, error:'Password change locked'})); return; }
    if (!pwdForm.current || !pwdForm.next) { setPwdForm(f=>({...f, error:'Fill all fields'})); return; }
    if (pwdForm.next !== pwdForm.confirm) { setPwdForm(f=>({...f, error:'Passwords do not match'})); return; }
    try {
      setPwdForm(f=>({...f, working:true, error:'' }));
      // Verify current password by attempting unlock
      await unlockWithPassword(pwdForm.current);
      // Derive new key and re-encrypt each file
      const oldKey = contentKey;
      const { createMasterPassword, decryptToArrayBuffer } = await import('./services/crypto.js');
      const newKey = await createMasterPassword(pwdForm.next); // overwrites stored hash
      const updated = [];
      for (const f of uploadedFiles) {
        try {
          if (f.data && f.iv) {
            const plain = await decryptToArrayBuffer(oldKey, f.iv, f.data);
            const enc = await encryptArrayBuffer(newKey, plain);
            updated.push({ ...f, iv: enc.iv, data: enc.data });
          } else { updated.push(f); }
        } catch { updated.push(f); }
      }
      setUploadedFiles(updated);
      setContentKey(newKey);
      setPwdForm({ current:'', next:'', confirm:'', working:false, error:'' });
      setShowPasswordModal(false);
      showNotificationMessage('Master password changed');
    } catch (e) {
      setPwdForm(f=>({...f, working:false, error:e.message || 'Failed'}));
    }
    */
  };

  // Inject auth gate overlay at top-level return
  return (
    <div className={`min-h-screen transition-colors duration-200 ${darkMode ? 'dark bg-gray-900 text-white' : 'bg-gray-50 text-gray-900'}`}>
      {!authState.unlocked && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-gray-900/80 px-4">
          <div className="w-full max-w-md bg-white dark:bg-gray-800 rounded-lg shadow-xl border border-gray-200 dark:border-gray-700 p-6">
            <div className="flex items-center mb-4">
              <div className="w-10 h-10 bg-blue-600 rounded-lg flex items-center justify-center text-white mr-3"><i className="fas fa-shield-alt"></i></div>
              <h2 className="text-xl font-semibold">
                {authState.stage === 'showRecovery' ? 'Recovery Key' : 
                 authState.mode === 'register' ? 'Create Account' : 'Sign In'}
              </h2>
            </div>
            
            {authState.error && <div className="mb-4 text-sm text-red-600 bg-red-50 dark:bg-red-900/30 p-2 rounded">{authState.error}</div>}
            
            {authState.stage === 'showRecovery' ? (
              // Recovery key display
              <div className="space-y-4">
                <div className="bg-yellow-50 dark:bg-yellow-900/30 border border-yellow-200 dark:border-yellow-700 rounded-lg p-4">
                  <div className="flex items-center mb-2">
                    <i className="fas fa-exclamation-triangle text-yellow-600 mr-2"></i>
                    <span className="font-medium text-yellow-800 dark:text-yellow-200">Important: Save Your Recovery Key</span>
                  </div>
                  <p className="text-sm text-yellow-700 dark:text-yellow-300 mb-3">
                    This key can restore access to your vault if you forget your password. Store it securely and never share it.
                  </p>
                  <div className="bg-white dark:bg-gray-800 border rounded p-3 font-mono text-sm break-all">
                    {recoveryKey}
                  </div>
                </div>
                <button 
                  onClick={handleRecoveryConfirm}
                  className="w-full px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-md font-medium"
                >
                  I've Saved My Recovery Key - Continue
                </button>
              </div>
            ) : (
              // Login/Register form
              <div className="space-y-4">
                {authState.mode === 'register' && (
                  <div>
                    <label className="block text-sm font-medium mb-1">Phone Number</label>
                    <input 
                      type="tel" 
                      value={authForm.phone} 
                      onChange={e=>setAuthForm(f=>({...f, phone:e.target.value}))} 
                      className="w-full rounded-md border border-gray-300 dark:border-gray-600 px-3 py-2 bg-white dark:bg-gray-700"
                      placeholder="For account recovery"
                    />
                  </div>
                )}
                
                <div>
                  <label className="block text-sm font-medium mb-1">Email</label>
                  <input 
                    type="email" 
                    value={authForm.email} 
                    onChange={e=>setAuthForm(f=>({...f, email:e.target.value}))} 
                    className="w-full rounded-md border border-gray-300 dark:border-gray-600 px-3 py-2 bg-white dark:bg-gray-700"
                    autoFocus={!authForm.email}
                  />
                </div>
                
                <div>
                  <label className="block text-sm font-medium mb-1">Password</label>
                  <input 
                    type="password" 
                    value={authForm.password} 
                    onChange={e=>setAuthForm(f=>({...f, password:e.target.value}))} 
                    className="w-full rounded-md border border-gray-300 dark:border-gray-600 px-3 py-2 bg-white dark:bg-gray-700"
                    autoFocus={!!authForm.email}
                  />
                </div>
                
                {authState.mode === 'register' && (
                  <div>
                    <label className="block text-sm font-medium mb-1">Confirm Password</label>
                    <input 
                      type="password" 
                      value={authForm.passwordConfirm} 
                      onChange={e=>setAuthForm(f=>({...f, passwordConfirm:e.target.value}))} 
                      className="w-full rounded-md border border-gray-300 dark:border-gray-600 px-3 py-2 bg-white dark:bg-gray-700"
                    />
                  </div>
                )}
                
                <button 
                  disabled={authState.working} 
                  onClick={authState.mode === 'register' ? handleRegister : handleLogin}
                  className="w-full inline-flex justify-center items-center px-4 py-2 rounded-md bg-blue-600 hover:bg-blue-700 text-white font-medium disabled:opacity-60"
                >
                  {authState.working && <i className="fas fa-circle-notch fa-spin mr-2"/>}
                  {authState.mode === 'register' ? 'Create Account' : 'Sign In'}
                </button>
                
                <div className="text-center">
                  <button 
                    onClick={() => {
                      setAuthState(a => ({ ...a, mode: a.mode === 'login' ? 'register' : 'login', error: '' }));
                      setAuthForm(f => ({ ...f, phone: '', password: '', passwordConfirm: '' }));
                    }}
                    className="text-sm text-blue-600 hover:text-blue-700"
                  >
                    {authState.mode === 'register' ? 'Already have an account? Sign In' : 'Need an account? Sign Up'}
                  </button>
                </div>
              </div>
            )}
            
            {authState.stage === 'form' && (
              <p className="mt-4 text-xs text-gray-500">
                {authState.mode === 'register' 
                  ? 'Your data is encrypted client-side. We cannot recover lost passwords.' 
                  : 'Your password never leaves this device. Keys are derived locally.'}
              </p>
            )}
          </div>
        </div>
      )}
      {/* Cloud auth guidance banner when anonymous auth is disabled / fails */}
  {/* Firebase remote auth banner removed. */}

      {/* Notification System */}
      <div 
        className={`fixed top-4 right-4 z-50 min-w-80 max-w-md p-4 rounded-lg shadow-lg flex items-center gap-3 transform transition-transform duration-300 ${
          showNotification ? 'translate-x-0' : 'translate-x-96'
        } ${
          notification.type === 'success' ? 'bg-green-50 dark:bg-green-900/30 border-l-4 border-green-500' :
          notification.type === 'error' ? 'bg-red-50 dark:bg-red-900/30 border-l-4 border-red-500' :
          'bg-yellow-50 dark:bg-yellow-900/30 border-l-4 border-yellow-500'
        }`}
      >
        <div className={`text-xl ${
          notification.type === 'success' ? 'text-green-600' :
          notification.type === 'error' ? 'text-red-600' :
          'text-yellow-600'
        }`}>
          {notification.type === 'success' && <i className="fas fa-check-circle"></i>}
          {notification.type === 'error' && <i className="fas fa-exclamation-circle"></i>}
          {notification.type === 'warning' && <i className="fas fa-exclamation-triangle"></i>}
        </div>
        <div className="flex-1">
          <p className="font-medium">{notification.message}</p>
        </div>
        <button 
          onClick={() => setShowNotification(false)}
          className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
        >
          <i className="fas fa-times"></i>
        </button>
      </div>
  {/* Firebase error/index banners removed */}
      {offlineMode && (
        <div className="fixed bottom-4 left-4 z-40 px-3 py-2 rounded-md bg-gray-800 text-gray-100 text-xs shadow flex items-center gap-3">
          <span>Offline mode (cloud disabled)</span>
          <button onClick={()=>{ setOfflineMode(false); if(authState.unlocked) loadRemoteFiles(); }} className="px-2 py-0.5 text-xs rounded bg-blue-600">Reconnect</button>
        </div>
      )}

      {/* Header */}
      <header className="bg-white dark:bg-gray-800 shadow-sm border-b border-gray-200 dark:border-gray-700 sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <div className="flex items-center">
                  <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center mr-2">
                    <i className="fas fa-shield-alt text-white text-sm"></i>
                  </div>
                  <span className="text-xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">SecureVault</span>
                </div>
              </div>
              <nav className="hidden md:ml-8 md:flex md:space-x-8">
                <button
                  onClick={() => setCurrentView('dashboard')}
                  className={`inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium ${
                    currentView === 'dashboard' 
                      ? 'border-blue-500 text-blue-600 dark:text-blue-400' 
                      : 'border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700 dark:text-gray-300 dark:hover:text-white'
                  }`}
                >
                  Dashboard
                </button>
                <button
                  onClick={() => setCurrentView('documents')}
                  className={`inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium ${
                    currentView === 'documents' 
                      ? 'border-blue-500 text-blue-600 dark:text-blue-400' 
                      : 'border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700 dark:text-gray-300 dark:hover:text-white'
                  }`}
                >
                  Documents
                </button>
                <button
                  onClick={() => setCurrentView('emergency')}
                  className={`inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium ${
                    currentView === 'emergency' 
                      ? 'border-blue-500 text-blue-600 dark:text-blue-400' 
                      : 'border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700 dark:text-gray-300 dark:hover:text-white'
                  }`}
                >
                  Emergency
                </button>
                <button
                  onClick={() => setCurrentView('settings')}
                  className={`inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium ${
                    currentView === 'settings' 
                      ? 'border-blue-500 text-blue-600 dark:text-blue-400' 
                      : 'border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700 dark:text-gray-300 dark:hover:text-white'
                  }`}
                >
                  Settings
                </button>
              </nav>
            </div>
            <div className="flex items-center">
              <button
                onClick={() => setDarkMode(!darkMode)}
                className="p-2 rounded-full text-gray-500 dark:text-gray-300 hover:text-gray-700 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-colors"
                aria-label="Toggle dark mode"
              >
                {darkMode ? (
                  <i className="fas fa-sun"></i>
                ) : (
                  <i className="fas fa-moon"></i>
                )}
              </button>
              <div className="ml-3 relative">
                <div>
                {import.meta.env.DEV && (
                  <div className="fixed bottom-2 right-2 z-50 text-[10px] leading-tight font-mono bg-black/70 text-gray-100 p-2 rounded shadow space-y-0.5 max-w-[240px]">
                    <div className="font-semibold text-xs">Debug Status</div>
                    <div className="flex items-center gap-1">
                      <span>Mongo:</span>
                      <span className={mongoConnected? 'text-green-400':'text-red-300'}>{mongoConnected===null? '...' : mongoConnected? 'connected' : 'disconnected'}</span>
                      <button
                        onClick={async()=>{ try { const st = await mongoStatus(); setMongoConnected(!!st.connected); if(st.connected && authState.unlocked) loadRemoteFiles(); } catch { setMongoConnected(false); } }}
                        className="ml-auto px-1.5 py-0.5 bg-gray-600/60 hover:bg-gray-500 rounded"
                      >↺</button>
                    </div>
                    <div>Unlocked: {String(authState.unlocked)}</div>
                    <div>offlineMode: {String(offlineMode)}</div>
                    <div>Files: {uploadedFiles.length}</div>
                    <button
                      onClick={()=>{ if(authState.unlocked) loadRemoteFiles(); }}
                      className="mt-1 w-full bg-blue-600/80 hover:bg-blue-600 text-white py-0.5 rounded text-[10px]"
                    >Reload Remote</button>
                  </div>
                )}
                  <div className="relative">
                    <button 
                      onClick={() => setShowUserMenu(!showUserMenu)}
                      className="flex items-center text-sm rounded-full focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500" 
                      id="user-menu-button"
                    >
                      <div className="h-8 w-8 rounded-full bg-blue-500 flex items-center justify-center text-white font-medium">
                        {user.name.split(' ').map(n => n[0]).join('')}
                      </div>
                    </button>
                    
                    {showUserMenu && (
                      <div className="absolute right-0 mt-2 w-48 bg-white dark:bg-gray-800 rounded-md shadow-lg py-1 border border-gray-200 dark:border-gray-700 z-50">
                        <button
                          onClick={() => {
                            setCurrentView('settings');
                            setShowUserMenu(false);
                          }}
                          className="block w-full text-left px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700"
                        >
                          <i className="fas fa-user mr-2"></i>
                          Profile & Settings
                        </button>
                        <button
                          onClick={handleLock}
                          className="block w-full text-left px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700"
                        >
                          <i className="fas fa-lock mr-2"></i>
                          Lock Vault
                        </button>
                        <button
                          onClick={() => {
                            handleLogout();
                            setShowUserMenu(false);
                          }}
                          className="block w-full text-left px-4 py-2 text-sm text-red-600 dark:text-red-400 hover:bg-gray-100 dark:hover:bg-gray-700"
                        >
                          <i className="fas fa-sign-out-alt mr-2"></i>
                          Logout
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* Mobile menu */}
      <div className="md:hidden bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700">
        <div className="px-2 pt-2 pb-3 space-y-1 sm:px-3">
          <button
            onClick={() => setCurrentView('dashboard')}
            className={`block w-full text-left pl-3 pr-4 py-2 border-l-4 text-base font-medium rounded-md ${
              currentView === 'dashboard' 
                ? 'bg-blue-50 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 border-blue-500' 
                : 'border-transparent text-gray-500 hover:bg-gray-50 dark:hover:bg-gray-700 hover:border-gray-300 hover:text-gray-700 dark:text-gray-300 dark:hover:text-white'
            }`}
          >
            Dashboard
          </button>
          <button
            onClick={() => setCurrentView('documents')}
            className={`block w-full text-left pl-3 pr-4 py-2 border-l-4 text-base font-medium rounded-md ${
              currentView === 'documents' 
                ? 'bg-blue-50 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 border-blue-500' 
                : 'border-transparent text-gray-500 hover:bg-gray-50 dark:hover:bg-gray-700 hover:border-gray-300 hover:text-gray-700 dark:text-gray-300 dark:hover:text-white'
            }`}
          >
            Documents
          </button>
          <button
            onClick={() => setCurrentView('emergency')}
            className={`block w-full text-left pl-3 pr-4 py-2 border-l-4 text-base font-medium rounded-md ${
              currentView === 'emergency' 
                ? 'bg-blue-50 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 border-blue-500' 
                : 'border-transparent text-gray-500 hover:bg-gray-50 dark:hover:bg-gray-700 hover:border-gray-300 hover:text-gray-700 dark:text-gray-300 dark:hover:text-white'
            }`}
          >
            Emergency
          </button>
          <button
            onClick={() => setCurrentView('settings')}
            className={`block w-full text-left pl-3 pr-4 py-2 border-l-4 text-base font-medium rounded-md ${
              currentView === 'settings' 
                ? 'bg-blue-50 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 border-blue-500' 
                : 'border-transparent text-gray-500 hover:bg-gray-50 dark:hover:bg-gray-700 hover:border-gray-300 hover:text-gray-700 dark:text-gray-300 dark:hover:text-white'
            }`}
          >
            Settings
          </button>
        </div>
      </div>

      {/* Main Content */}
      <main className="flex-1">
        <div className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
          {currentView === 'dashboard' && (
            <div className="px-4 py-6 sm:px-0">
              {/* Welcome Section */}
              <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-8">
                <div>
                  <h1 className="text-2xl font-semibold text-gray-900 dark:text-white">Welcome back, {user.name.split(' ')[0]}</h1>
                  <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">Your personal vault is secured with end-to-end encryption</p>
                </div>
                <div className="mt-4 md:mt-0 flex items-center space-x-4">
                  <div className="flex items-center text-sm text-gray-500 dark:text-gray-400">
                    <i className="fas fa-lock mr-2"></i>
                    <span className="bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent font-medium">End-to-End Encrypted</span>
                  </div>
                  <div className="flex items-center text-sm text-gray-500 dark:text-gray-400">
                    <i className="fas fa-shield-alt mr-2"></i>
                    <span>Zero-Knowledge</span>
                  </div>
                </div>
              </div>

              {/* Security Status */}
              <div className="bg-gradient-to-r from-blue-50 to-indigo-50 dark:from-blue-900/20 dark:to-indigo-900/20 rounded-lg p-6 mb-8 border border-blue-100 dark:border-blue-800">
                <div className="flex items-center justify-between">
                  <div className="flex items-center">
                    <div className="flex-shrink-0">
                      <i className="fas fa-shield-alt text-blue-600 dark:text-blue-400 text-2xl"></i>
                    </div>
                    <div className="ml-4">
                      <h3 className="text-lg font-medium text-gray-900 dark:text-white">Security Status</h3>
                      <p className="text-sm text-gray-500 dark:text-gray-400">Your vault is fully protected</p>
                    </div>
                  </div>
                  <div className="flex items-center space-x-4">
                    <div className="flex items-center text-sm text-green-600 dark:text-green-400">
                      <i className="fas fa-check-circle mr-1"></i>
                      <span>2FA Enabled</span>
                    </div>
                    <div className="flex items-center text-sm text-green-600 dark:text-green-400">
                      <i className="fas fa-check-circle mr-1"></i>
                      <span>Encryption Active</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Quick Actions */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
                <div 
                  onClick={() => setCurrentView('documents')}
                  className="bg-white dark:bg-gray-800 rounded-lg p-6 shadow-sm border border-gray-200 dark:border-gray-700 hover:shadow-md transition-all duration-200 cursor-pointer transform hover:-translate-y-1"
                >
                  <div className="flex items-center">
                    <div className="flex-shrink-0 bg-blue-100 dark:bg-blue-900/30 rounded-md p-3">
                      <i className="fas fa-upload text-blue-600 dark:text-blue-400"></i>
                    </div>
                    <div className="ml-5 w-0 flex-1">
                      <dl>
                        <dt className="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">Upload Document</dt>
                        <dd className="flex items-baseline">
                          <div className="text-lg font-semibold text-gray-900 dark:text-white">New</div>
                        </dd>
                      </dl>
                    </div>
                  </div>
                </div>

                <div 
                  onClick={() => setCurrentView('emergency')}
                  className="bg-white dark:bg-gray-800 rounded-lg p-6 shadow-sm border border-gray-200 dark:border-gray-700 hover:shadow-md transition-all duration-200 cursor-pointer transform hover:-translate-y-1"
                >
                  <div className="flex items-center">
                    <div className="flex-shrink-0 bg-green-100 dark:bg-green-900/30 rounded-md p-3">
                      <i className="fas fa-share-alt text-green-600 dark:text-green-400"></i>
                    </div>
                    <div className="ml-5 w-0 flex-1">
                      <dl>
                        <dt className="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">Share Access</dt>
                        <dd className="flex items-baseline">
                          <div className="text-lg font-semibold text-gray-900 dark:text-white">Emergency</div>
                        </dd>
                      </dl>
                    </div>
                  </div>
                </div>

                <div 
                  onClick={() => setCurrentView('emergency')}
                  className="bg-white dark:bg-gray-800 rounded-lg p-6 shadow-sm border border-gray-200 dark:border-gray-700 hover:shadow-md transition-all duration-200 cursor-pointer transform hover:-translate-y-1"
                >
                  <div className="flex items-center">
                    <div className="flex-shrink-0 bg-purple-100 dark:bg-purple-900/30 rounded-md p-3">
                      <i className="fas fa-user-shield text-purple-600 dark:text-purple-400"></i>
                    </div>
                    <div className="ml-5 w-0 flex-1">
                      <dl>
                        <dt className="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">Trusted Contacts</dt>
                        <dd className="flex items-baseline">
                          <div className="text-lg font-semibold text-gray-900 dark:text-white">{trustedContacts.length}</div>
                        </dd>
                      </dl>
                    </div>
                  </div>
                </div>

                <div className="bg-white dark:bg-gray-800 rounded-lg p-6 shadow-sm border border-gray-200 dark:border-gray-700 hover:shadow-md transition-all duration-200 transform hover:-translate-y-1">
                  <div className="flex items-center">
                    <div className="flex-shrink-0 bg-orange-100 dark:bg-orange-900/30 rounded-md p-3">
                      <i className="fas fa-history text-orange-600 dark:text-orange-400"></i>
                    </div>
                    <div className="ml-5 w-0 flex-1">
                      <dl>
                        <dt className="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">Recent Activity</dt>
                        <dd className="flex items-baseline">
                          <div className="text-lg font-semibold text-gray-900 dark:text-white">{uploadedFiles.length}</div>
                        </dd>
                      </dl>
                    </div>
                  </div>
                </div>
              </div>

              {/* Storage Usage (dynamic) */}
              {/* Cloudinary Status */}
              <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6 mb-8">
                <div className="flex items-start justify-between mb-4">
                  <div>
                    <h3 className="text-lg font-medium text-gray-900 dark:text-white flex items-center gap-2">
                      <i className="fas fa-cloud-upload-alt text-blue-600 dark:text-blue-400"></i>
                      Cloudinary Status
                    </h3>
                    <p className="text-sm text-gray-500 dark:text-gray-400">Encrypted blobs stored via Cloudinary raw uploads</p>
                  </div>
                  <div className="flex items-center gap-2">
                    {import.meta.env.VITE_CLOUDINARY_CLOUD_NAME ? (
                      <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400"><i className="fas fa-check mr-1"/>Configured</span>
                    ) : (
                      <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400"><i className="fas fa-times mr-1"/>Missing Env</span>
                    )}
                  </div>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                  <div className="space-y-1">
                    <p className="text-gray-500 dark:text-gray-400">Cloud Name</p>
                    <p className="font-mono text-xs break-all text-gray-800 dark:text-gray-200">{import.meta.env.VITE_CLOUDINARY_CLOUD_NAME || 'ΓÇö'}</p>
                  </div>
                  <div className="space-y-1">
                    <p className="text-gray-500 dark:text-gray-400">Unsigned Preset</p>
                    <p className="font-mono text-xs break-all text-gray-800 dark:text-gray-200">{import.meta.env.VITE_CLOUDINARY_UPLOAD_PRESET || 'ΓÇö'}</p>
                  </div>
                  <div className="space-y-1">
                    <p className="text-gray-500 dark:text-gray-400">Files w/ Cloudinary ID</p>
                    <p className="font-semibold">{uploadedFiles.filter(f=>f.cloudinaryId).length} / {uploadedFiles.length}</p>
                  </div>
                </div>
                {lastCloudinaryError && (
                  <div className="mt-3 text-xs text-red-700 dark:text-red-300 bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 p-2 rounded flex items-start gap-2">
                    <i className="fas fa-exclamation-triangle mt-0.5"/>
                    <span className="flex-1">Last Cloudinary error: {lastCloudinaryError}</span>
                    <button onClick={()=>setLastCloudinaryError(null)} className="text-[10px] px-1.5 py-0.5 rounded bg-red-100 dark:bg-red-900/50">Dismiss</button>
                  </div>
                )}
                <div className="mt-4">
                  <div className="flex flex-wrap gap-2">
                    {uploadedFiles.filter(f=>f.cloudinaryId).slice(0,5).map(f => (
                      <span key={f.id} className="inline-flex items-center px-2 py-0.5 rounded text-[10px] bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300" title={f.cloudinaryId}>{f.name.length>14? f.name.slice(0,12)+'ΓÇª': f.name}</span>
                    ))}
                    {uploadedFiles.filter(f=>f.cloudinaryId).length===0 && (
                      <span className="text-xs text-gray-500 dark:text-gray-400">No Cloudinary-backed files yet</span>
                    )}
                  </div>
                </div>
                {!import.meta.env.VITE_CLOUDINARY_CLOUD_NAME && (
                  <div className="mt-4 text-xs text-yellow-700 dark:text-yellow-300 bg-yellow-50 dark:bg-yellow-900/30 border border-yellow-200 dark:border-yellow-800 p-3 rounded">
                    Add VITE_CLOUDINARY_CLOUD_NAME and VITE_CLOUDINARY_UPLOAD_PRESET to .env.local then restart dev server.
                  </div>
                )}
              </div>
              <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6 mb-8">
                <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">Storage Usage</h3>
                <div className="space-y-4">
                  <div>
                    <div className="flex justify-between text-sm mb-1">
                      <span className="text-gray-600 dark:text-gray-400">Used: {(totalBytes/1024/1024).toFixed(2)} MB</span>
                      <span className="text-gray-600 dark:text-gray-400">Limit: {(storageLimit/1024/1024/1024).toFixed(0)} GB</span>
                    </div>
                    <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2.5 overflow-hidden">
                      <div className="bg-blue-600 h-2.5" style={{ width: `${usedPercent.toFixed(1)}%` }}></div>
                    </div>
                  </div>
                  <p className="text-sm text-gray-500 dark:text-gray-400">You're using {usedPercent.toFixed(1)}% of your storage.</p>
                </div>
              </div>

              {/* Recent Activity */}
              <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-lg font-medium text-gray-900 dark:text-white">Recent Activity</h3>
                  <button disabled={activityLog.length===0} onClick={()=>{ setActivityLog([]); }} className="text-xs px-2 py-1 rounded border border-gray-300 dark:border-gray-600 disabled:opacity-40">Clear</button>
                </div>
                <div className="space-y-3">
                  {activityLog.length === 0 && <p className="text-sm text-gray-500 dark:text-gray-400">No recent activity</p>}
                  {activityLog.slice(0,6).map(a => (
                    <div key={a.ts + a.id} className="flex items-center justify-between text-xs p-2 rounded border border-gray-200 dark:border-gray-700">
                      <div className="flex-1 min-w-0">
                        <p className="font-medium text-gray-800 dark:text-gray-200 truncate">{a.name}</p>
                        <p className="text-[10px] text-gray-500 dark:text-gray-400">{a.action} ΓÇó {(a.size/1024).toFixed(1)} KB ΓÇó {new Date(a.ts).toLocaleTimeString()}</p>
                      </div>
                      <span className="ml-2 inline-flex items-center px-1.5 py-0.5 rounded text-[10px] bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300">Mongo</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {currentView === 'documents' && (
            <div className="px-4 py-6 sm:px-0">
              <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-6">
                <h1 className="text-2xl font-semibold text-gray-900 dark:text-white">Your Documents</h1>
                <div className="mt-4 md:mt-0 flex items-center space-x-2">
                  <div className="relative">
                    <input
                      type="text"
                      placeholder="Search documents..."
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                      className="pl-10 pr-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 w-full md:w-64"
                    />
                    <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                      <i className="fas fa-search text-gray-400 dark:text-gray-500"></i>
                    </div>
                  </div>
                  <select
                    value={selectedCategory}
                    onChange={(e) => setSelectedCategory(e.target.value)}
                    className="rounded-md border border-gray-300 dark:border-gray-600 px-3 py-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    <option value="all">All Categories</option>
                    {folders.map(folder => (
                      <option key={folder.name} value={folder.name}>{folder.name}</option>
                    ))}
                  </select>
                </div>
              </div>

              {/* Upload Section */}
              <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6 mb-8">
                <div className="flex items-center justify-between mb-6">
                  <h2 className="text-lg font-medium text-gray-900 dark:text-white">Upload New Document</h2>
                  <div className="flex items-center space-x-2">
                    <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400">
                      <i className="fas fa-lock mr-1"></i>
                      Encrypted
                    </span>
                  </div>
                </div>
                
                <div
                  onDragEnter={handleDragEnter}
                  onDragOver={handleDragOver}
                  onDragLeave={handleDragLeave}
                  onDrop={handleDrop}
                  className={`rounded-lg border-2 border-dashed p-8 text-center cursor-pointer transition-all duration-200 ${
                    isDragging 
                      ? 'border-green-500 bg-green-50 dark:bg-green-900/20' 
                      : 'border-gray-300 dark:border-gray-600 hover:border-blue-400 dark:hover:border-blue-500'
                  }`}
                  onClick={() => fileInputRef.current?.click()}
                >
                  <i className={`fas fa-cloud-upload-alt text-4xl mb-4 ${isDragging ? 'text-green-500' : 'text-gray-400 dark:text-gray-500'}`}></i>
                  <p className="text-lg font-medium text-gray-700 dark:text-gray-300 mb-2">
                    {isDragging ? 'Drop files to upload' : 'Drag & drop files here'}
                  </p>
                  <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">or click to browse (PDF, JPG, PNG, DOCX)</p>
                  <div className="inline-flex items-center px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-md transition-colors">
                    Choose Files
                  </div>
                  <input
                    ref={fileInputRef}
                    type="file"
                    multiple
                    accept=".pdf,.jpg,.jpeg,.png,.doc,.docx,.txt,.xls,.xlsx"
                    onChange={handleFileInputChange}
                    className="hidden"
                  />
                </div>
                
                <div className="mt-6">
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Document Category</label>
                  <select
                    value={selectedCategory}
                    onChange={(e) => setSelectedCategory(e.target.value)}
                    className="w-full rounded-md border border-gray-300 dark:border-gray-600 px-3 py-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    <option value="all">Select Category</option>
                    {folders.map(folder => (
                      <option key={folder.name} value={folder.name}>{folder.name}</option>
                    ))}
                  </select>
                </div>
              </div>

              {/* Folders */}
              <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6 mb-8">
                <h3 className="text-md font-medium text-gray-900 dark:text-white mb-4">Categories</h3>
                <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-6">
                  {folders.map((folder) => (
                    <div key={folder.name} className="text-center cursor-pointer transform hover:scale-105 transition-transform">
                      <div className={`w-12 h-12 ${folder.bgColor} dark:bg-opacity-30 rounded-md flex items-center justify-center mx-auto mb-2`}>
                        <i className="fas fa-folder text-2xl opacity-80"></i>
                      </div>
                      <p className="text-sm font-medium text-gray-700 dark:text-gray-300">{folder.name}</p>
                      <p className="text-xs text-gray-500 dark:text-gray-400">{folder.count} files</p>
                    </div>
                  ))}
                </div>
              </div>

              {/* Document List */}
              <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700">
                <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
                  <h3 className="text-md font-medium text-gray-900 dark:text-white">Documents ({filteredFiles.length})</h3>
                </div>
                <div className="divide-y divide-gray-200 dark:divide-gray-700">
                  {loadingFiles && (
                    <div className="p-4 flex items-center text-sm text-gray-500 dark:text-gray-400 gap-3">
                      <i className="fas fa-circle-notch fa-spin"></i>
                      Loading encrypted documents...
                    </div>
                  )}
                  {filteredFiles.length > 0 ? (
                    filteredFiles.map((file) => {
                      const progress = uploadProgress[file.id] || uploadProgress[`temp-${file.id}`];
                      return (
                      <div key={file.id} className="p-4 hover:bg-gray-50 dark:hover:bg-gray-750 transition-colors relative">
                        {file.uploading && (
                          <div className="absolute inset-0 bg-white/70 dark:bg-gray-900/70 flex flex-col items-center justify-center text-xs font-medium">
                            <div className="w-40 h-2 bg-gray-200 dark:bg-gray-700 rounded overflow-hidden mb-2">
                              <div className="h-2 bg-blue-600 transition-all" style={{width: `${(uploadProgress[file.id]||0).toFixed(1)}%`}}></div>
                            </div>
                            <span>{(uploadProgress[file.id]||0).toFixed(1)}%</span>
                          </div>
                        )}
                        <div className="flex items-center">
                          <div className="flex-shrink-0 text-2xl">
                            {getFileIcon(file.type)}
                          </div>
                          <div className="ml-4 flex-1">
                            <h4 className="text-sm font-medium text-gray-900 dark:text-white flex items-center gap-2">
                              {file.name}
                              {file.docId && <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-300"><i className="fas fa-cloud mr-1"/>Cloud</span>}
                            </h4>
                            <div className="flex flex-wrap gap-2 mt-1">
                              <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400">{file.category}</span>
                              <span className="text-xs text-gray-500 dark:text-gray-400">{file.size}</span>
                              <span className="text-xs text-gray-500 dark:text-gray-400">{file.date}</span>
                              {file.error && <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400">Failed</span>}
                              {file.needsReencrypt && <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400" title="Legacy item missing encrypted payload; re-upload to sync">Re-upload</span>}
                              {file.cloudError && <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400" title={file.cloudError}>Cloud Err</span>}
                            </div>
                          </div>
                          <div className="flex items-center space-x-2">
                            <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${file.error ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400' : 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400'}`}><i className={`fas ${file.error ? 'fa-exclamation-triangle mr-1' : 'fa-lock mr-1'}`}></i>{file.uploading? 'Encrypting' : file.error ? 'Error' : 'Encrypted'}</span>
                            {file.error && (
                              <button onClick={()=>retryFailedUpload(file)} className="px-2 py-1 text-xs rounded bg-yellow-500 text-white hover:bg-yellow-600" title="Retry encryption & upload">Retry</button>
                            )}
                            {file.needsReencrypt && (
                              <button onClick={()=>chooseLegacyReupload(file)} className="px-2 py-1 text-xs rounded bg-yellow-600 text-white hover:bg-yellow-700" title="Select original file to re-encrypt">Replace</button>
                            )}
                            <button disabled={file.uploading || file.error || !file.encrypted} onClick={()=>previewFile(file)} className="p-1 text-indigo-500 hover:text-indigo-600 disabled:opacity-40" title="Preview"><i className="fas fa-eye"/></button>
                            <button disabled={file.uploading || file.error || !file.encrypted} onClick={()=>downloadFile(file)} className="p-1 text-blue-500 hover:text-blue-600 disabled:opacity-40" title="Download"><i className="fas fa-download"/></button>
                            {!file.cloudinaryId && file.encrypted && !file.error && !file.uploading && import.meta.env.VITE_CLOUDINARY_UPLOAD_PRESET && (
                              <button onClick={()=>backfillCloudinary(file)} className="p-1 text-teal-500 hover:text-teal-600" title="Upload encrypted blob to Cloudinary"><i className="fas fa-cloud-upload"/></button>
                            )}
                            <button onClick={()=>deleteFile(file.id)} className="p-1 text-red-500 hover:text-red-600" title="Delete"><i className="fas fa-trash"/></button>
                          </div>
                        </div>
                      </div>
                      );
                    })
                  ) : (
                    <div className="p-8 text-center">
                      <i className="fas fa-folder-open text-4xl text-gray-300 dark:text-gray-600 mb-4"></i>
                      <p className="text-gray-500 dark:text-gray-400">No documents found</p>
                      <p className="text-sm text-gray-400 dark:text-gray-500 mt-1">Try adjusting your search or category filter</p>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {currentView === 'emergency' && (
            <div className="px-4 py-6 sm:px-0">
              <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-6">
                <div>
                  <h1 className="text-2xl font-semibold text-gray-900 dark:text-white">Emergency Access</h1>
                  <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">Manage trusted contacts who can access your vault in case of emergency</p>
                </div>
              </div>

              {/* Emergency Access Settings */}
              <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6 mb-8">
                <div className="flex items-start">
                  <div className="flex-shrink-0">
                    <div className="w-12 h-12 bg-red-100 dark:bg-red-900/30 rounded-full flex items-center justify-center">
                      <i className="fas fa-exclamation-triangle text-red-600 dark:text-red-400"></i>
                    </div>
                  </div>
                  <div className="ml-4 flex-1">
                    <h3 className="text-lg font-medium text-gray-900 dark:text-white">Emergency Access</h3>
                    <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                      Designate trusted contacts who can request access to your vault if something happens to you. 
                      You can set a waiting period (30 days recommended) before access is granted.
                    </p>
                    <div className="mt-4">
                      <button onClick={enableEmergency} className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-red-600 hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500">
                        {emergencyConfig.enabled ? 'Emergency Enabled' : 'Set Up Emergency Access'}
                      </button>
                    </div>
                  </div>
                </div>
              </div>

              {/* Trusted Contacts */}
              <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
                <div className="flex justify-between items-center mb-6">
                  <h2 className="text-lg font-medium text-gray-900 dark:text-white">Trusted Contacts ({contacts.length})</h2>
                  <button onClick={()=>setShowContactModal(true)} className="inline-flex items-center px-3 py-1.5 border border-transparent text-sm font-medium rounded-md text-blue-700 bg-blue-100 hover:bg-blue-200 dark:bg-blue-900/30 dark:text-blue-400 dark:hover:bg-blue-900/50">
                    <i className="fas fa-plus mr-1"></i>
                    Add Contact
                  </button>
                </div>

                <div className="space-y-4">
                  {contacts.map((contact) => (
                    <div key={contact.id} className="flex items-center p-4 border border-gray-200 dark:border-gray-700 rounded-lg">
                      <div className="flex-shrink-0 h-10 w-10 rounded-full bg-blue-500 flex items-center justify-center text-white font-medium">
                        {contact.name.split(' ').map(n => n[0]).join('')}
                      </div>
                      <div className="ml-4 flex-1">
                        <div className="flex items-center">
                          <h3 className="text-sm font-medium text-gray-900 dark:text-white">{contact.name}</h3>
                          <span className="ml-2 inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300">
                            {contact.relationship}
                          </span>
                        </div>
                        <p className="text-sm text-gray-500 dark:text-gray-400">{contact.email}</p>
                      </div>
                      <div className="flex items-center space-x-3">
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                          contact.accessLevel === 'Full Access' ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400' :
                          contact.accessLevel === 'Emergency' ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400' :
                          'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400'
                        }`}>
                          {contact.accessLevel}
                        </span>
                        <button onClick={()=>removeContact(contact.id)} className="p-1 text-red-500 hover:text-red-600 rounded hover:bg-red-50 dark:hover:bg-red-900/30" title="Remove">
                          <i className="fas fa-trash"></i>
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* One-Time Access Links */}
              <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6 mt-8">
                <h2 className="text-lg font-medium text-gray-900 dark:text-white mb-4">One-Time Access Links</h2>
                <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
                  Generate secure, time-limited links to share specific documents with others.
                </p>
                <div className="flex flex-col sm:flex-row gap-4">
                  <select value={linkForm.fileId} onChange={e=>setLinkForm(f=>({...f,fileId:e.target.value, error:''}))} className="rounded-md border border-gray-300 dark:border-gray-600 px-3 py-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500">
                    <option value="">Select Document</option>
                    {uploadedFiles.map(file => (
                      <option key={file.id} value={file.id}>{file.name}</option>
                    ))}
                  </select>
                  <select value={linkForm.expiry} onChange={e=>setLinkForm(f=>({...f,expiry:e.target.value, error:''}))} className="rounded-md border border-gray-300 dark:border-gray-600 px-3 py-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500">
                    <option value="7d">7 days</option>
                    <option value="1d">1 day</option>
                    <option value="1h">1 hour</option>
                    <option value="30m">30 minutes</option>
                  </select>
                  <button onClick={generateLink} disabled={!linkForm.fileId} className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 disabled:opacity-50 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
                    Generate Link
                  </button>
                </div>
                {linkForm.error && <p className="mt-3 text-sm text-red-600 dark:text-red-400">{linkForm.error}</p>}
                {oneTimeLinks.length > 0 && (
                  <div className="mt-6 space-y-3">
          {oneTimeLinks.map(l => (
                      <div key={l.id} className="flex items-center justify-between text-sm p-3 rounded-md border border-gray-200 dark:border-gray-700">
                        <div className="flex-1 min-w-0">
              <p className="font-medium text-gray-800 dark:text-gray-200 truncate">{l.accessUrl || `${window.location.origin}/share/${l.id}`}</p>
              <p className="text-xs text-gray-500 dark:text-gray-400">Expires {new Date(l.expiresAt || l.createdAt).toLocaleString()}</p>
                        </div>
                        <div className="flex items-center gap-2 ml-4">
              <button onClick={()=>{navigator.clipboard.writeText(l.accessUrl || `${window.location.origin}/share/${l.id}`); showNotificationMessage('Link copied');}} className="px-2 py-1 text-xs rounded bg-gray-200 dark:bg-gray-700">Copy</button>
              <button onClick={()=>revokeLink(l.id)} className="px-2 py-1 text-xs rounded bg-red-500 text-white">Revoke</button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {currentView === 'settings' && (
            <div className="px-4 py-6 sm:px-0">
              <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-6">
                <h1 className="text-2xl font-semibold text-gray-900 dark:text-white">Settings</h1>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Account Settings */}
                <div className="lg:col-span-2">
                  <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6 mb-6">
                    <h2 className="text-lg font-medium text-gray-900 dark:text-white mb-6">Account Settings</h2>
                    
                    <div className="space-y-6">
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Full Name</label>
                        <input
                          type="text"
                          defaultValue={user.name}
                          className="w-full rounded-md border border-gray-300 dark:border-gray-600 px-3 py-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                        />
                      </div>
                      
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Email Address</label>
                        <input
                          type="email"
                          defaultValue={user.email}
                          className="w-full rounded-md border border-gray-300 dark:border-gray-600 px-3 py-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                        />
                      </div>
                      
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Phone Number</label>
                        <input
                          type="tel"
                          placeholder="+1 (555) 123-4567"
                          className="w-full rounded-md border border-gray-300 dark:border-gray-600 px-3 py-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                        />
                      </div>
                    </div>
                  </div>

                  {/* Security Settings */}
                  <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6 mb-6">
                    <h2 className="text-lg font-medium text-gray-900 dark:text-white mb-6">Security Settings</h2>
                    
                    <div className="space-y-6">
                      <div className="flex items-center justify-between">
                        <div>
                          <h3 className="text-sm font-medium text-gray-900 dark:text-white">Two-Factor Authentication</h3>
                          <p className="text-sm text-gray-500 dark:text-gray-400">Add an extra layer of security to your account</p>
                        </div>
                        <button onClick={()=>toggleSetting('twoFactor')} className={`inline-flex items-center px-3 py-1.5 border border-transparent text-sm font-medium rounded-md ${settingsState.twoFactor ? 'text-green-700 bg-green-100 dark:bg-green-900/30 dark:text-green-400' : 'text-blue-700 bg-blue-100 dark:bg-blue-900/30 dark:text-blue-400'} hover:opacity-90`}>
                          {settingsState.twoFactor ? 'Enabled' : 'Enable'}
                        </button>
                      </div>
                      
                      <div className="flex items-center justify-between">
                        <div>
                          <h3 className="text-sm font-medium text-gray-900 dark:text-white">Password</h3>
                          <p className="text-sm text-gray-500 dark:text-gray-400">Update your password</p>
                        </div>
                        {import.meta.env.VITE_LOCK_MASTER_PASSWORD === 'true' ? (
                          <span className="inline-flex items-center px-3 py-1.5 text-xs font-medium rounded-md bg-gray-200 dark:bg-gray-700 text-gray-600 dark:text-gray-300" title="Locked by env">Locked</span>
                        ) : (
                          <button onClick={()=>setShowPasswordModal(true)} className="inline-flex items-center px-3 py-1.5 border border-transparent text-sm font-medium rounded-md text-blue-700 bg-blue-100 hover:bg-blue-200 dark:bg-blue-900/30 dark:text-blue-400 dark:hover:bg-blue-900/50">
                            Change
                          </button>
                        )}
                      </div>
                      
                      <div className="flex items-center justify-between">
                        <div>
                          <h3 className="text-sm font-medium text-gray-900 dark:text-white">Encryption Key</h3>
                          <p className="text-sm text-gray-500 dark:text-gray-400">Manage your encryption keys</p>
                        </div>
                        <button className="inline-flex items-center px-3 py-1.5 border border-transparent text-sm font-medium rounded-md text-blue-700 bg-blue-100 hover:bg-blue-200 dark:bg-blue-900/30 dark:text-blue-400 dark:hover:bg-blue-900/50">
                          Manage
                        </button>
                      </div>
                      
                      <div className="flex items-center justify-between">
                        <div>
                          <h3 className="text-sm font-medium text-gray-900 dark:text-white">Session Management</h3>
                          <p className="text-sm text-gray-500 dark:text-gray-400">Active sessions and devices</p>
                        </div>
                        <button className="inline-flex items-center px-3 py-1.5 border border-transparent text-sm font-medium rounded-md text-blue-700 bg-blue-100 hover:bg-blue-200 dark:bg-blue-900/30 dark:text-blue-400 dark:hover:bg-blue-900/50">
                          View
                        </button>
                      </div>
                    </div>
                  </div>

                  {/* Notification Settings */}
                  <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
                    <h2 className="text-lg font-medium text-gray-900 dark:text-white mb-6">Notification Settings</h2>
                    
                    <div className="space-y-4">
                      <div className="flex items-center justify-between">
                        <div>
                          <h3 className="text-sm font-medium text-gray-900 dark:text-white">Email Notifications</h3>
                          <p className="text-sm text-gray-500 dark:text-gray-400">Receive email alerts for important events</p>
                        </div>
                        <button onClick={()=>toggleSetting('emailNotif')} className={`relative inline-flex h-6 w-11 items-center rounded-full transition ${settingsState.emailNotif ? 'bg-blue-600' : 'bg-gray-400 dark:bg-gray-600'}`}>
                          <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition ${settingsState.emailNotif ? 'translate-x-6' : 'translate-x-1'}`}></span>
                        </button>
                      </div>
                      
                      <div className="flex items-center justify-between">
                        <div>
                          <h3 className="text-sm font-medium text-gray-900 dark:text-white">Push Notifications</h3>
                          <p className="text-sm text-gray-500 dark:text-gray-400">Get alerts on your devices</p>
                        </div>
                        <button onClick={()=>toggleSetting('pushNotif')} className={`relative inline-flex h-6 w-11 items-center rounded-full transition ${settingsState.pushNotif ? 'bg-blue-600' : 'bg-gray-400 dark:bg-gray-600'}`}>
                          <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition ${settingsState.pushNotif ? 'translate-x-6' : 'translate-x-1'}`}></span>
                        </button>
                      </div>
                      
                      <div className="flex items-center justify-between">
                        <div>
                          <h3 className="text-sm font-medium text-gray-900 dark:text-white">Access Alerts</h3>
                          <p className="text-sm text-gray-500 dark:text-gray-400">Notify when someone accesses your vault</p>
                        </div>
                        <button onClick={()=>toggleSetting('accessAlerts')} className={`relative inline-flex h-6 w-11 items-center rounded-full transition ${settingsState.accessAlerts ? 'bg-blue-600' : 'bg-gray-400 dark:bg-gray-600'}`}>
                          <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition ${settingsState.accessAlerts ? 'translate-x-6' : 'translate-x-1'}`}></span>
                        </button>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Security Overview */}
                <div>
                  <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
                    <h2 className="text-lg font-medium text-gray-900 dark:text-white mb-4">Security Overview</h2>
                    
                    <div className="space-y-4">
                      <div className="flex items-center">
                        <div className="flex-shrink-0">
                          <i className="fas fa-shield-alt text-green-500"></i>
                        </div>
                        <div className="ml-3">
                          <p className="text-sm font-medium text-gray-900 dark:text-white">Account Security</p>
                          <p className="text-sm text-green-600 dark:text-green-400">Protected with 2FA</p>
                        </div>
                      </div>
                      
                      <div className="flex items-center">
                        <div className="flex-shrink-0">
                          <i className="fas fa-lock text-green-500"></i>
                        </div>
                        <div className="ml-3">
                          <p className="text-sm font-medium text-gray-900 dark:text-white">Data Encryption</p>
                          <p className="text-sm text-green-600 dark:text-green-400">AES-256 end-to-end encryption</p>
                        </div>
                      </div>
                      
                      <div className="flex items-center">
                        <div className="flex-shrink-0">
                          <i className="fas fa-sync text-blue-500"></i>
                        </div>
                        <div className="ml-3">
                          <p className="text-sm font-medium text-gray-900 dark:text-white">Last Sync</p>
                          <p className="text-sm text-gray-500 dark:text-gray-400">Just now</p>
                        </div>
                      </div>
                      
                      <div className="flex items-center">
                        <div className="flex-shrink-0">
                          <i className="fas fa-sign-in-alt text-gray-500"></i>
                        </div>
                        <div className="ml-3">
                          <p className="text-sm font-medium text-gray-900 dark:text-white">Last Login</p>
                          <p className="text-sm text-gray-500 dark:text-gray-400">{securityStatus.lastLogin}</p>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Backup Settings */}
                  <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6 mt-6">
                    <h2 className="text-lg font-medium text-gray-900 dark:text-white mb-4">Backup Settings</h2>
                    
                    <div className="space-y-4">
                      <div className="flex items-center justify-between">
                        <div>
                          <h3 className="text-sm font-medium text-gray-900 dark:text-white">Cloud Backup</h3>
                          <p className="text-sm text-gray-500 dark:text-gray-400">Automatically backup to secure cloud storage</p>
                        </div>
                        <button onClick={()=>toggleSetting('cloudBackup')} className={`relative inline-flex h-6 w-11 items-center rounded-full transition ${settingsState.cloudBackup ? 'bg-blue-600' : 'bg-gray-400 dark:bg-gray-600'}`}>
                          <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition ${settingsState.cloudBackup ? 'translate-x-6' : 'translate-x-1'}`}></span>
                        </button>
                      </div>
                      
                      <div className="flex items-center justify-between">
                        <div>
                          <h3 className="text-sm font-medium text-gray-900 dark:text-white">Local Backup</h3>
                          <p className="text-sm text-gray-500 dark:text-gray-400">Export encrypted backup to local device</p>
                        </div>
                        <button className="inline-flex items-center px-3 py-1.5 border border-transparent text-sm font-medium rounded-md text-blue-700 bg-blue-100 hover:bg-blue-200 dark:bg-blue-900/30 dark:text-blue-400 dark:hover:bg-blue-900/50">
                          Export
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </main>

      {/* Footer */}
      <footer className="bg-white dark:bg-gray-800 border-t border-gray-200 dark:border-gray-700">
        <div className="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8">
          <div className="md:flex md:items-center md:justify-between">
            <div className="flex justify-center md:justify-start space-x-6">
              <div className="flex items-center">
                <i className="fas fa-shield-alt text-blue-600 mr-2"></i>
                <span className="text-sm text-gray-500 dark:text-gray-400">End-to-End Encrypted</span>
              </div>
              <div className="flex items-center">
                <i className="fas fa-lock text-gray-500 dark:text-gray-400 mr-2"></i>
                <span className="text-sm text-gray-500 dark:text-gray-400">Zero-Knowledge Architecture</span>
              </div>
            </div>
            <p className="mt-4 text-center md:mt-0 md:text-right text-sm text-gray-500 dark:text-gray-400">
              &copy; 2023 SecureVault. All rights reserved.
            </p>
          </div>
        </div>
      </footer>

      {/* UI PATCHES BELOW (add modal portals at end before footer) */}
      {showContactModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
          <div className="bg-white dark:bg-gray-800 w-full max-w-md rounded-lg p-6 border border-gray-200 dark:border-gray-700">
            <h3 className="text-lg font-semibold mb-4">Add Trusted Contact</h3>
            <div className="space-y-4">
              <input className="w-full px-3 py-2 rounded-md border dark:border-gray-600 bg-white dark:bg-gray-700" placeholder="Full name" value={contactForm.name} onChange={e=>setContactForm(f=>({...f, name:e.target.value}))} />
              <input className="w-full px-3 py-2 rounded-md border dark:border-gray-600 bg-white dark:bg-gray-700" placeholder="Email" type="email" value={contactForm.email} onChange={e=>setContactForm(f=>({...f, email:e.target.value}))} />
              <select className="w-full px-3 py-2 rounded-md border dark:border-gray-600 bg-white dark:bg-gray-700" value={contactForm.relationship} onChange={e=>setContactForm(f=>({...f, relationship:e.target.value}))}>
                <option>Friend</option><option>Family</option><option>Spouse</option><option>Attorney</option>
              </select>
              <select className="w-full px-3 py-2 rounded-md border dark:border-gray-600 bg-white dark:bg-gray-700" value={contactForm.accessLevel} onChange={e=>setContactForm(f=>({...f, accessLevel:e.target.value}))}>
                <option>View Only</option><option>Emergency</option><option>Full Access</option>
              </select>
              <div className="flex justify-end gap-2 pt-2">
                <button onClick={()=>setShowContactModal(false)} className="px-4 py-2 rounded-md border dark:border-gray-600">Cancel</button>
                <button onClick={addContact} className="px-4 py-2 rounded-md bg-blue-600 text-white">Add</button>
              </div>
            </div>
          </div>
        </div>
      )}
  {/* Hidden input for legacy replacement */}
  <input ref={legacyReuploadInputRef} type="file" className="hidden" onChange={handleLegacyReuploadChange} />
      {showPasswordModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
          <div className="bg-white dark:bg-gray-800 w-full max-w-md rounded-lg p-6 border border-gray-200 dark:border-gray-700">
            <h3 className="text-lg font-semibold mb-4">Change Master Password</h3>
            {pwdForm.error && <div className="text-sm text-red-600 mb-2">{pwdForm.error}</div>}
            <div className="space-y-3">
              <input type="password" placeholder="Current password" value={pwdForm.current} onChange={e=>setPwdForm(f=>({...f, current:e.target.value}))} className="w-full px-3 py-2 rounded-md border dark:border-gray-600 bg-white dark:bg-gray-700" />
              <input type="password" placeholder="New password" value={pwdForm.next} onChange={e=>setPwdForm(f=>({...f, next:e.target.value}))} className="w-full px-3 py-2 rounded-md border dark:border-gray-600 bg-white dark:bg-gray-700" />
              <input type="password" placeholder="Confirm new password" value={pwdForm.confirm} onChange={e=>setPwdForm(f=>({...f, confirm:e.target.value}))} className="w-full px-3 py-2 rounded-md border dark:border-gray-600 bg-white dark:bg-gray-700" />
              <button disabled={pwdForm.working} onClick={changeMasterPassword} className="w-full inline-flex justify-center items-center px-4 py-2 rounded-md bg-blue-600 text-white disabled:opacity-60">{pwdForm.working && <i className="fas fa-circle-notch fa-spin mr-2"/>}Change Password</button>
              <p className="text-xs text-gray-500">All documents will be re-encrypted. Do not close the tab.</p>
              <button onClick={()=>setShowPasswordModal(false)} className="w-full mt-2 px-4 py-2 rounded-md border dark:border-gray-600">Cancel</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default App;
