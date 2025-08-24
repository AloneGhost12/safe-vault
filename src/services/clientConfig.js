// Dynamic client configuration fetcher with fallback to baked-in Vite env vars
export async function getClientConfig() {
  const fallback = {
    cloudName: import.meta.env.VITE_CLOUDINARY_CLOUD_NAME || null,
    uploadPreset: import.meta.env.VITE_CLOUDINARY_UPLOAD_PRESET || null,
  };
  try {
    const res = await fetch((import.meta.env.VITE_API_BASE_URL || '') + '/api/client-config', { cache: 'no-store' });
    if (!res.ok) throw new Error('Config fetch failed');
    const json = await res.json();
    return {
      cloudName: json.cloudName || fallback.cloudName,
      uploadPreset: json.uploadPreset || fallback.uploadPreset
    };
  } catch (e) {
    console.warn('Client config fallback', e.message);
    return fallback;
  }
}
