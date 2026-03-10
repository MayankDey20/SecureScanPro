/**
 * Supabase JS client — optional, used for Realtime subscriptions only.
 *
 * Auth is handled by the backend JWT system (AuthContext.jsx / api.js).
 * This client is only active when VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY
 * are set in the environment. If they are absent the module exports null-safe
 * stubs so the rest of the app still compiles and runs without Supabase.
 *
 * Usage:
 *   import { supabase, isSupabaseEnabled } from '@/lib/supabase';
 *   // or use the hooks:
 *   import { useRealtimeScan, useRealtimeScanList } from '@/lib/supabase';
 */
import { useEffect, useRef } from 'react';
import { createClient } from '@supabase/supabase-js';

const SUPABASE_URL  = import.meta.env.VITE_SUPABASE_URL;
const SUPABASE_ANON = import.meta.env.VITE_SUPABASE_ANON_KEY;

export const isSupabaseEnabled = !!(SUPABASE_URL && SUPABASE_ANON);

// ── Initialise the Supabase JS client ───────────────────────────────────────
let _client = null;

if (isSupabaseEnabled) {
  try {
    _client = createClient(SUPABASE_URL, SUPABASE_ANON, {
      auth: {
        // We manage auth ourselves via JWT — disable Supabase's session persistence
        persistSession: false,
        autoRefreshToken: false,
        detectSessionInUrl: false,
      },
    });
  } catch (e) {
    console.warn('[Supabase] Failed to initialise client:', e.message);
  }
}

export const supabase = _client;
export const getSupabase = () => _client;

// ── useRealtimeScan ─────────────────────────────────────────────────────────
/**
 * React hook that subscribes to real-time updates for a specific scan row.
 *
 * @param {string|null} scanId   - UUID of the scan to watch (null = no subscription)
 * @param {function}    onUpdate - Called with the updated scan row whenever a change arrives
 *
 * @example
 *   useRealtimeScan(scanId, (updated) => setScan(updated));
 */
export function useRealtimeScan(scanId, onUpdate) {
  const channelRef = useRef(null);

  useEffect(() => {
    if (!scanId || !_client) return;

    if (channelRef.current) {
      _client.removeChannel(channelRef.current);
    }

    const channel = _client
      .channel(`scan-${scanId}`)
      .on(
        'postgres_changes',
        {
          event: 'UPDATE',
          schema: 'public',
          table: 'scans',
          filter: `id=eq.${scanId}`,
        },
        (payload) => {
          if (payload.new) onUpdate(payload.new);
        }
      )
      .subscribe((status) => {
        if (status === 'SUBSCRIBED') {
          console.debug(`[Realtime] Watching scan ${scanId}`);
        }
      });

    channelRef.current = channel;

    return () => {
      if (_client && channelRef.current) {
        _client.removeChannel(channelRef.current);
        channelRef.current = null;
      }
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId]);
}


// ── useRealtimeScanList ──────────────────────────────────────────────────────
/**
 * Hook that fires onInsert / onUpdate whenever any scan row changes for the
 * given userId. Useful for keeping the scan history list live.
 *
 * @param {string|null} userId
 * @param {{ onInsert?: fn, onUpdate?: fn }} callbacks
 */
export function useRealtimeScanList(userId, { onInsert, onUpdate } = {}) {
  const channelRef = useRef(null);

  useEffect(() => {
    if (!userId || !_client) return;

    if (channelRef.current) {
      _client.removeChannel(channelRef.current);
    }

    const channel = _client
      .channel(`scan-list-${userId}`)
      .on(
        'postgres_changes',
        {
          event: 'INSERT',
          schema: 'public',
          table: 'scans',
          filter: `user_id=eq.${userId}`,
        },
        (payload) => onInsert?.(payload.new)
      )
      .on(
        'postgres_changes',
        {
          event: 'UPDATE',
          schema: 'public',
          table: 'scans',
          filter: `user_id=eq.${userId}`,
        },
        (payload) => onUpdate?.(payload.new)
      )
      .subscribe();

    channelRef.current = channel;

    return () => {
      if (_client && channelRef.current) {
        _client.removeChannel(channelRef.current);
        channelRef.current = null;
      }
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [userId]);
}
