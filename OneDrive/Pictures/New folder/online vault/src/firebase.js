// Firebase initialization isolated here. Avoid hard-coding sensitive keys directly in code you commit publicly.
// Consider moving config to environment variables (e.g., import.meta.env) before publishing.
import { initializeApp } from 'firebase/app';
import { getAnalytics, isSupported } from 'firebase/analytics';
import { getFirestore, setLogLevel } from 'firebase/firestore';
import { getDatabase } from 'firebase/database';
import { getAuth } from 'firebase/auth';

const firebaseConfig = {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY || 'AIzaSyB3yhXS53MONoFuuMtuCdenAs102LMgITE',
  authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN || 'digital-vault-e8525.firebaseapp.com',
  projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID || 'digital-vault-e8525',
  messagingSenderId: import.meta.env.VITE_FIREBASE_SENDER_ID || '131281672942',
  appId: import.meta.env.VITE_FIREBASE_APP_ID || '1:131281672942:web:bc0232b92f1564c6eb31ff',
  measurementId: import.meta.env.VITE_FIREBASE_MEASUREMENT_ID || 'G-3R5F2QEB91'
};

const app = initializeApp(firebaseConfig);
export const db = getFirestore(app);
// Optional verbose Firestore logging (set VITE_FIRESTORE_DEBUG=true in .env.local)
try { if (import.meta.env.VITE_FIRESTORE_DEBUG === 'true') setLogLevel('debug'); } catch {}
export const rtdb = getDatabase(app);
export const auth = getAuth(app);
let analytics; // Only enable if supported (won't work in some SSR / Node contexts)
(async () => { if (await isSupported()) analytics = getAnalytics(app); })();

export { app };
