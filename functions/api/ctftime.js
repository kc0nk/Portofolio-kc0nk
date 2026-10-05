const TEAM_ID = 434825;
const YEAR = 2026;
const COUNTRY = 'ID';
const TEAM_NAME = 'KOMANDO 71';

export async function onRequestGet({ request }) {
  const cache = caches.default;
  const cacheKey = new Request(new URL(request.url).toString(), request);
  const cached = await cache.match(cacheKey);
  if (cached) return cached;

  try {
    const apiUrl = `https://ctftime.org/api/v1/teams/${TEAM_ID}/`;
    const statsUrl = `https://ctftime.org/stats/${YEAR}/${COUNTRY}`;
    const headers = {
      'User-Agent': 'KOMANDO71-Website/1.0'
    };

    const [teamResponse, statsResponse] = await Promise.all([
      fetch(apiUrl, { headers }),
      fetch(statsUrl, { headers })
    ]);

    if (!teamResponse.ok) throw new Error(`CTFtime team API HTTP ${teamResponse.status}`);
    if (!statsResponse.ok) throw new Error(`CTFtime stats HTTP ${statsResponse.status}`);

    const team = await teamResponse.json();
    const statsHtml = await statsResponse.text();
    const statsText = statsHtml
      .replace(/<script[\s\S]*?<\/script>/gi, ' ')
      .replace(/<style[\s\S]*?<\/style>/gi, ' ')
      .replace(/<[^>]+>/g, ' ')
      .replace(/&nbsp;/gi, ' ')
      .replace(/&amp;/gi, '&')
      .replace(/&#39;/gi, "'")
      .replace(/&quot;/gi, '"')
      .replace(/\s+/g, ' ')
      .trim();

    const escapedName = TEAM_NAME.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const rowRegex = new RegExp(`(\\d+)\\s+(\\d+)\\s+${escapedName}\\s+([\\d.]+)\\s+(\\d+)`, 'i');
    const match = statsText.match(rowRegex);

    if (!match) throw new Error('KOMANDO 71 was not found in the CTFtime Indonesia ranking');

    const stats = {
      team: team.name || TEAM_NAME,
      teamId: TEAM_ID,
      year: YEAR,
      worldRank: Number(match[1]),
      countryRank: Number(match[2]),
      ratingPoints: Number(String(team.rating ?? match[3]).replace(/,/g, '')),
      events: Number(match[4]),
      country: 'Indonesia',
      updatedAt: new Date().toISOString(),
      source: apiUrl,
      rankingSource: statsUrl
    };

    const response = new Response(JSON.stringify(stats), {
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'public, max-age=300, s-maxage=300',
        'Access-Control-Allow-Origin': '*'
      }
    });

    await cache.put(cacheKey, response.clone());
    return response;
  } catch (error) {
    return new Response(JSON.stringify({
      error: 'Unable to fetch live CTFtime data',
      message: error instanceof Error ? error.message : String(error)
    }), {
      status: 502,
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Access-Control-Allow-Origin': '*'
      }
    });
  }
}
