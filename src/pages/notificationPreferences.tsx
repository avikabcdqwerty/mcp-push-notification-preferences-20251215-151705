import React, { useEffect, useState } from 'react';
import type { NextPage, GetServerSidePropsContext } from 'next';
import type { NextApiRequest, NextApiResponse } from 'next';
import type { PrismaClient } from '@prisma/client';
import { getSession } from 'next-auth/react';
import { useRouter } from 'next/router';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import axios from 'axios';

// --- Constants and Config ---
const EVENT_TYPES = [
  { key: 'order_created', label: 'Order Created' },
  { key: 'order_shipped', label: 'Order Shipped' },
  { key: 'order_delivered', label: 'Order Delivered' },
  { key: 'promotion', label: 'Promotions' },
  // Add more event types as needed
];

const ENCRYPTION_ALGO = 'aes-256-gcm';
const ENCRYPTION_KEY = process.env.PREFS_ENCRYPTION_KEY || ''; // 32 bytes base64
const ENCRYPTION_IV_LENGTH = 12; // For GCM

const JWT_SECRET = process.env.JWT_SECRET || 'supersecret';

// --- Utility: Encryption/Decryption ---
function encryptPreferences(preferences: Record<string, boolean>): string {
  const iv = crypto.randomBytes(ENCRYPTION_IV_LENGTH);
  const key = Buffer.from(ENCRYPTION_KEY, 'base64');
  const cipher = crypto.createCipheriv(ENCRYPTION_ALGO, key, iv);
  const json = JSON.stringify(preferences);
  let encrypted = cipher.update(json, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  const tag = cipher.getAuthTag();
  return [
    iv.toString('base64'),
    tag.toString('base64'),
    encrypted,
  ].join(':');
}

function decryptPreferences(encrypted: string): Record<string, boolean> {
  if (!encrypted) return {};
  const [ivB64, tagB64, encryptedData] = encrypted.split(':');
  const iv = Buffer.from(ivB64, 'base64');
  const tag = Buffer.from(tagB64, 'base64');
  const key = Buffer.from(ENCRYPTION_KEY, 'base64');
  const decipher = crypto.createDecipheriv(ENCRYPTION_ALGO, key, iv);
  decipher.setAuthTag(tag);
  let decrypted = decipher.update(encryptedData, 'base64', 'utf8');
  decrypted += decipher.final('utf8');
  return JSON.parse(decrypted);
}

// --- Utility: JWT Authentication ---
function verifyJWT(token: string): { userId: string } | null {
  try {
    const payload = jwt.verify(token, JWT_SECRET) as { userId: string };
    return payload;
  } catch {
    return null;
  }
}

// --- Utility: Push Notification Stub ---
async function sendPushNotification(userId: string, eventType: string, payload: any) {
  // Stub: Integrate with Firebase/OneSignal/etc.
  // For demonstration, just log
  console.log(
    `[PushNotification] Sent to user ${userId} for event ${eventType}:`,
    payload
  );
}

// --- Prisma Client Loader ---
let prisma: PrismaClient | undefined;
async function getPrisma(): Promise<PrismaClient> {
  if (prisma) return prisma;
  const { PrismaClient } = await import('@prisma/client');
  prisma = new PrismaClient();
  return prisma;
}

// --- API Route Handler ---
export async function notificationPreferencesApi(
  req: NextApiRequest,
  res: NextApiResponse
) {
  try {
    // Auth: JWT in Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    const token = authHeader.slice(7);
    const user = verifyJWT(token);
    if (!user) {
      return res.status(401).json({ error: 'Invalid token' });
    }
    const userId = user.userId;

    const prisma = await getPrisma();

    if (req.method === 'GET') {
      // Fetch preferences
      const record = await prisma.notificationPreferences.findUnique({
        where: { userId },
      });
      let prefs: Record<string, boolean> = {};
      if (record && record.preferencesEncrypted) {
        prefs = decryptPreferences(record.preferencesEncrypted);
      }
      // Ensure all event types are present
      const result: Record<string, boolean> = {};
      EVENT_TYPES.forEach((et) => {
        result[et.key] = prefs[et.key] ?? true; // default enabled
      });
      return res.status(200).json({ preferences: result });
    }

    if (req.method === 'PUT') {
      // Update preferences
      const { preferences } = req.body;
      if (
        !preferences ||
        typeof preferences !== 'object' ||
        Array.isArray(preferences)
      ) {
        return res.status(400).json({ error: 'Invalid preferences format' });
      }
      // Validate event types
      for (const key of Object.keys(preferences)) {
        if (!EVENT_TYPES.find((et) => et.key === key)) {
          return res.status(400).json({ error: `Unknown event type: ${key}` });
        }
        if (typeof preferences[key] !== 'boolean') {
          return res.status(400).json({ error: `Invalid value for ${key}` });
        }
      }
      // Encrypt and save atomically
      const encrypted = encryptPreferences(preferences);
      await prisma.$transaction(async (tx) => {
        await tx.notificationPreferences.upsert({
          where: { userId },
          update: { preferencesEncrypted: encrypted },
          create: { userId, preferencesEncrypted: encrypted },
        });
      });
      return res.status(200).json({ success: true });
    }

    return res.status(405).json({ error: 'Method not allowed' });
  } catch (err: any) {
    console.error('[API Error]', err);
    return res
      .status(500)
      .json({ error: 'Internal server error', details: err.message });
  }
}

// --- API Route Export (Next.js API Route) ---
export const config = {
  api: {
    bodyParser: true,
    externalResolver: true,
  },
};

if (typeof window === 'undefined') {
  // Only register API route on server
  // Next.js API route: /api/notificationPreferences
  // This is a hack for colocated API in pages (for demonstration)
  // In production, move to /pages/api/notificationPreferences.ts
  // @ts-ignore
  if (!global.__notificationPreferencesApiRegistered) {
    // @ts-ignore
    global.__notificationPreferencesApiRegistered = true;
    // @ts-ignore
    require('next/dist/server/api-utils').setApiRoute(
      '/api/notificationPreferences',
      notificationPreferencesApi
    );
  }
}

// --- Frontend: Notification Preferences Page ---
type PreferencesMap = Record<string, boolean>;

const NotificationPreferencesPage: NextPage = () => {
  const [preferences, setPreferences] = useState<PreferencesMap>({});
  const [loading, setLoading] = useState<boolean>(true);
  const [saving, setSaving] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const router = useRouter();

  // Get JWT from next-auth session
  const [jwtToken, setJwtToken] = useState<string | null>(null);

  useEffect(() => {
    async function fetchSession() {
      const session = await getSession();
      if (!session || !session.user || !session.user.id) {
        router.replace('/login');
        return;
      }
      // Assume JWT is in session.accessToken
      setJwtToken(session.accessToken as string);
    }
    fetchSession();
  }, [router]);

  useEffect(() => {
    if (!jwtToken) return;
    async function fetchPreferences() {
      setLoading(true);
      setError(null);
      try {
        const res = await axios.get('/api/notificationPreferences', {
          headers: { Authorization: `Bearer ${jwtToken}` },
        });
        setPreferences(res.data.preferences);
      } catch (err: any) {
        setError(
          err.response?.data?.error ||
            'Failed to load preferences. Please try again.'
        );
      } finally {
        setLoading(false);
      }
    }
    fetchPreferences();
  }, [jwtToken]);

  const handleToggle = (eventType: string) => {
    setPreferences((prev) => ({
      ...prev,
      [eventType]: !prev[eventType],
    }));
    setSuccess(null);
    setError(null);
  };

  const handleSave = async () => {
    setSaving(true);
    setError(null);
    setSuccess(null);
    try {
      await axios.put(
        '/api/notificationPreferences',
        { preferences },
        { headers: { Authorization: `Bearer ${jwtToken}` } }
      );
      setSuccess('Preferences updated successfully.');
    } catch (err: any) {
      setError(
        err.response?.data?.error ||
          'Failed to update preferences. No changes were saved.'
      );
      // Reload preferences to prevent partial updates
      try {
        const res = await axios.get('/api/notificationPreferences', {
          headers: { Authorization: `Bearer ${jwtToken}` },
        });
        setPreferences(res.data.preferences);
      } catch {
        // Ignore
      }
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="container" style={{ maxWidth: 600, margin: '2rem auto' }}>
      <h1>Push Notification Preferences</h1>
      <p>
        Manage which event types you receive push notifications for. Changes are
        saved securely and take effect immediately.
      </p>
      {loading ? (
        <div>Loading preferences...</div>
      ) : (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSave();
          }}
        >
          <ul style={{ listStyle: 'none', padding: 0 }}>
            {EVENT_TYPES.map((et) => (
              <li
                key={et.key}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  marginBottom: '1rem',
                }}
              >
                <label style={{ flex: 1 }}>
                  <strong>{et.label}</strong>
                </label>
                <input
                  type="checkbox"
                  checked={preferences[et.key] ?? true}
                  onChange={() => handleToggle(et.key)}
                  disabled={saving}
                  aria-label={`Enable push notifications for ${et.label}`}
                />
                <span style={{ marginLeft: 8 }}>
                  {preferences[et.key] ? 'Enabled' : 'Disabled'}
                </span>
              </li>
            ))}
          </ul>
          <button
            type="submit"
            disabled={saving}
            style={{
              padding: '0.5rem 1.5rem',
              fontSize: '1rem',
              background: '#0070f3',
              color: '#fff',
              border: 'none',
              borderRadius: 4,
              cursor: saving ? 'not-allowed' : 'pointer',
            }}
          >
            {saving ? 'Saving...' : 'Save Preferences'}
          </button>
          {error && (
            <div
              style={{
                color: 'red',
                marginTop: '1rem',
                background: '#ffeaea',
                padding: '0.5rem',
                borderRadius: 4,
              }}
            >
              {error}
            </div>
          )}
          {success && (
            <div
              style={{
                color: 'green',
                marginTop: '1rem',
                background: '#eaffea',
                padding: '0.5rem',
                borderRadius: 4,
              }}
            >
              {success}
            </div>
          )}
        </form>
      )}
      <style jsx>{`
        .container {
          background: #fff;
          border-radius: 8px;
          box-shadow: 0 2px 8px rgba(0, 0, 0, 0.07);
          padding: 2rem;
        }
      `}</style>
    </div>
  );
};

export default NotificationPreferencesPage;

// --- Server-side Push Notification Trigger Example ---
// This would be called from your event system when an event occurs
// Ensures push notification is sent only for enabled event types within 60s
export async function triggerPushNotificationForEvent(
  userId: string,
  eventType: string,
  payload: any
) {
  const prisma = await getPrisma();
  const record = await prisma.notificationPreferences.findUnique({
    where: { userId },
  });
  let prefs: Record<string, boolean> = {};
  if (record && record.preferencesEncrypted) {
    prefs = decryptPreferences(record.preferencesEncrypted);
  }
  // Default: enabled if not set
  const enabled = prefs[eventType] ?? true;
  if (!enabled) {
    console.log(
      `[PushNotification] Skipped for user ${userId} (disabled for ${eventType})`
    );
    return;
  }
  // Send notification within 60s
  setTimeout(() => {
    sendPushNotification(userId, eventType, payload);
  }, Math.min(60000, 1000)); // For demo, send after 1s, but max 60s
}

// --- Documentation ---
// API Endpoints:
//   GET /api/notificationPreferences
//     - Returns: { preferences: { [eventType]: boolean } }
//   PUT /api/notificationPreferences
//     - Body: { preferences: { [eventType]: boolean } }
//     - Returns: { success: true }
//   Auth: Bearer JWT in Authorization header
//   Preferences are encrypted at rest in DB

// UI Usage:
//   - Accessible only to authenticated users
//   - Lists all supported event types with current status
//   - Allows enable/disable per event type
//   - Changes are atomic and confirmed
//   - Error messages shown on failure, no partial updates

// Security:
//   - Preferences encrypted with AES-256-GCM
//   - Only authenticated user can access/modify their own settings
//   - JWT authentication required for API

// Testing:
//   - Designed for Jest unit/integration tests
//   - All business logic modularized for testability