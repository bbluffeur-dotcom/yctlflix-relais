const URLRE = /^https?:\/\/\S+$/i;
export function parseLine(raw) {
  let line = raw.trim();
  if (!line) return null;
  // séparateurs : | ; , tabulation, espaces
  const tokens = (line.includes('|') ? line.split('|') : line.split(/[\s;,]+/)).map(t => t.trim()).filter(Boolean);
  // adresse = DERNIÈRE adresse http(s) de la ligne
  let u = -1; tokens.forEach((t, i) => { if (/^https?:\/\//i.test(t)) u = i; });
  if (u < 0) return { error: "aucune adresse http:// ou https://" };
  let server = tokens[u], user, pass;
  const before = tokens.slice(0, u).filter(t => !/^https?:\/\//i.test(t));
  let after = tokens.slice(u + 1);
  // lien get.php / player_api.php
  const q = server.match(/[?&]username=([^&]+).*?[?&]password=([^&]+)/i) || server.match(/[?&]password=([^&]+).*?[?&]username=([^&]+)/i);
  if (q && /username=([^&]+)/i.test(server)) {
    user = decodeURIComponent(server.match(/username=([^&]+)/i)[1]);
    pass = decodeURIComponent(server.match(/password=([^&]+)/i)[1]);
  }
  // mots-clés
  const all = [...before, ...after];
  const kw = (names) => { const i = all.findIndex(t => names.includes(t.toLowerCase().replace(/:$/, ''))); return i >= 0 ? all[i + 1] : undefined; };
  const kuser = kw(['user','username','id','login','utilisateur']), kpass = kw(['mdp','pass','password','motdepasse','pwd']);
  let name;
  if (!user && (kuser || kpass)) {
    user = kuser; pass = kpass;
    name = before.filter(t => !/^(user|username|id|login|utilisateur|mdp|pass|password|motdepasse|pwd):?$/i.test(t) && t !== kuser && t !== kpass).join(' ');
  } else if (!user) {
    if (after.length === 2) { user = after[0]; pass = after[1]; name = before.join(' '); }
    else if (after.length === 0 && before.length >= 2) { // "user mdp lien" non pris en charge
      return { error: "identifiant et mot de passe doivent suivre l'adresse" };
    } else if (after.length > 2) { user = after[0]; pass = after[1]; name = before.join(' '); return { error: `éléments en trop après le mot de passe : ${after.slice(2).join(' ')}` }; }
    else return { error: after.length === 1 ? 'mot de passe manquant' : 'identifiant et mot de passe manquants' };
  } else name = before.join(' ');
  // adresse normalisée
  let o; try { o = new URL(server); } catch { return { error: 'adresse invalide' }; }
  const port = (o.protocol === 'http:' && o.port === '80') || (o.protocol === 'https:' && o.port === '443') ? '' : o.port;
  const norm = `${o.protocol}//${o.hostname}${port ? ':' + port : ''}`;
  if (!user) return { error: 'identifiant manquant' };
  if (!pass) return { error: 'mot de passe manquant' };
  return { name: name || o.hostname, server: norm, user, pass };
}
