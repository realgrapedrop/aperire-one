/**
 * The rippled.cfg reader, the four settings the config runbook may change.
 *
 * Pure parsing, split out of server.ts when #59 taught it the two stanza-
 * shaped settings. The file format has two shapes and only one of them was
 * handled before, which is why "what is node_size" had no answer anywhere in
 * the read surface:
 *
 *   [node_db]                  a section of key=value lines
 *   online_delete=32768
 *   advisory_delete=1
 *
 *   [node_size]                a section whose whole value is the next line
 *   huge
 *
 * Reading only the FIRST line of a bare stanza is deliberate. A stanza with
 * two lines under it is not one of these four settings, and taking the last
 * line would report a value rippled never used.
 *
 * Nothing here reads a file or keeps state, server.ts still owns when the
 * file is read and what is cached. This is the half that has edge cases, so
 * it is the half that gets tested.
 */

export interface RippledCfgSettings {
  /** `[node_db]`'s `online_delete`, or null when the line is absent. */
  online_delete: number | null;
  /** `[node_db]`'s `advisory_delete`, or null when the line is absent. */
  advisory_delete: boolean | null;
  /** `[node_size]`'s value, as written. Null when the stanza is absent,
   *  which is rippled's own default of `tiny`, the absence is the fact, and
   *  filling in the default here would report a value the file does not
   *  contain. */
  node_size: string | null;
  /** `[ledger_history]`'s value, as written: a count, or the word `full`.
   *  Null when absent. */
  ledger_history: string | null;
}

/** The stanzas whose whole value is the line underneath the header. */
const BARE_STANZAS = new Set(['node_size', 'ledger_history']);

export function parseRippledCfg(text: string): RippledCfgSettings {
  const out: RippledCfgSettings = {
    online_delete: null, advisory_delete: null,
    node_size: null, ledger_history: null,
  };
  let inNodeDb = false;
  // The bare stanza currently open, or ''. Set by its own header, and
  // cleared by the next header or by the first value line it takes.
  let bareStanza = '';
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    if (line.startsWith('[') && line.endsWith(']')) {
      inNodeDb = line === '[node_db]';
      const name = line.slice(1, -1).trim();
      bareStanza = BARE_STANZAS.has(name) ? name : '';
      continue;
    }
    if (bareStanza) {
      // First line wins, and a repeated stanza does not overwrite the first
      // one either: rippled itself takes the first.
      if (bareStanza === 'node_size' && out.node_size === null) out.node_size = line;
      else if (bareStanza === 'ledger_history' && out.ledger_history === null) out.ledger_history = line;
      bareStanza = '';
      continue;
    }
    if (!inNodeDb) continue;
    const eq = line.indexOf('=');
    if (eq < 0) continue;
    const key = line.slice(0, eq).trim();
    const val = line.slice(eq + 1).trim();
    if (key === 'online_delete') out.online_delete = Number.parseInt(val, 10) || null;
    else if (key === 'advisory_delete') out.advisory_delete = val === '1' || val.toLowerCase() === 'true';
  }
  return out;
}
