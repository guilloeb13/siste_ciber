import React, { useState, useEffect } from 'react';

function CTFPanel({ apiUrl, token }) {
  const [challenges, setChallenges] = useState([]);
  const [scoreboard, setScoreboard] = useState([]);
  const [teamToken, setTeamToken] = useState('');
  const [submitFlag, setSubmitFlag] = useState({ challengeId: '', flag: '' });
  const [message, setMessage] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const headers = {
        'Authorization': `Bearer ${token}`,
      };

      // Fetch challenges
      const challengesRes = await fetch(`${apiUrl}/api/ctf/challenges`, { headers });
      if (challengesRes.ok) {
        setChallenges(await challengesRes.json());
      }

      // Fetch scoreboard
      const scoreboardRes = await fetch(`${apiUrl}/api/ctf/scoreboard`, { headers });
      if (scoreboardRes.ok) {
        setScoreboard(await scoreboardRes.json());
      }

    } catch (error) {
      console.error('Failed to fetch CTF data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmitFlag = async (e) => {
    e.preventDefault();
    setMessage(null);

    try {
      const response = await fetch(`${apiUrl}/api/ctf/submit`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          team_token: teamToken,
          challenge_id: submitFlag.challengeId,
          flag: submitFlag.flag,
        }),
      });

      const data = await response.json();

      if (data.correct) {
        setMessage({ type: 'success', text: `Correct! +${data.points} points` });
        fetchData(); // Refresh scoreboard
      } else {
        setMessage({ type: 'error', text: data.message });
      }

      setSubmitFlag({ ...submitFlag, flag: '' });

    } catch (error) {
      setMessage({ type: 'error', text: 'Failed to submit flag' });
    }
  };

  const categoryColor = (category) => {
    const colors = {
      web: 'bg-blue-900 text-blue-200',
      forensic: 'bg-purple-900 text-purple-200',
      crypto: 'bg-yellow-900 text-yellow-200',
      misc: 'bg-gray-700 text-gray-200',
      network: 'bg-green-900 text-green-200',
      binary: 'bg-red-900 text-red-200',
      configuration: 'bg-orange-900 text-orange-200',
    };
    return colors[category] || 'bg-gray-700 text-gray-200';
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="text-gray-400">Loading CTF data...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-white">CTF Training</h1>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Challenges */}
        <div className="lg:col-span-2 space-y-4">
          <h2 className="text-lg font-semibold text-white">Challenges</h2>

          {challenges.length === 0 ? (
            <div className="bg-gray-800 rounded-lg p-6 text-center text-gray-400">
              No active challenges
            </div>
          ) : (
            challenges.map((challenge) => (
              <div key={challenge.id} className="bg-gray-800 rounded-lg p-4">
                <div className="flex justify-between items-start">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className={`px-2 py-1 rounded text-xs font-medium ${categoryColor(challenge.category)}`}>
                        {challenge.category}
                      </span>
                      <span className="text-green-400 font-medium">{challenge.points} pts</span>
                    </div>
                    <h3 className="text-lg font-medium text-white mt-2">{challenge.name}</h3>
                    <p className="text-gray-400 mt-1 text-sm">{challenge.description}</p>

                    {challenge.hints && challenge.hints.length > 0 && (
                      <div className="mt-3">
                        <details className="text-sm">
                          <summary className="text-yellow-400 cursor-pointer">Hints ({challenge.hints.length})</summary>
                          <ul className="mt-2 space-y-1">
                            {challenge.hints.map((hint, i) => (
                              <li key={i} className="text-gray-400">• {hint}</li>
                            ))}
                          </ul>
                        </details>
                      </div>
                    )}
                  </div>
                  <div className="text-right">
                    <span className="text-gray-500 text-sm">{challenge.solves} solves</span>
                  </div>
                </div>

                {/* Flag submission for this challenge */}
                <div className="mt-4 pt-4 border-t border-gray-700">
                  <form onSubmit={handleSubmitFlag} className="flex gap-2">
                    <input
                      type="text"
                      placeholder="Enter flag..."
                      value={submitFlag.challengeId === challenge.id ? submitFlag.flag : ''}
                      onChange={(e) => setSubmitFlag({ challengeId: challenge.id, flag: e.target.value })}
                      className="flex-1 bg-gray-700 text-white rounded px-3 py-2 text-sm"
                    />
                    <button
                      type="submit"
                      disabled={submitFlag.challengeId !== challenge.id || !submitFlag.flag}
                      className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded text-sm disabled:opacity-50"
                    >
                      Submit
                    </button>
                  </form>
                </div>
              </div>
            ))
          )}
        </div>

        {/* Sidebar */}
        <div className="space-y-6">
          {/* Team Token */}
          <div className="bg-gray-800 rounded-lg p-4">
            <h3 className="text-md font-semibold text-white mb-3">Team Token</h3>
            <input
              type="text"
              placeholder="Enter your team token"
              value={teamToken}
              onChange={(e) => setTeamToken(e.target.value)}
              className="w-full bg-gray-700 text-white rounded px-3 py-2 text-sm"
            />
          </div>

          {/* Message */}
          {message && (
            <div className={`p-3 rounded ${
              message.type === 'success' ? 'bg-green-900 text-green-200' : 'bg-red-900 text-red-200'
            }`}>
              {message.text}
            </div>
          )}

          {/* Scoreboard */}
          <div className="bg-gray-800 rounded-lg p-4">
            <h3 className="text-md font-semibold text-white mb-3">Scoreboard</h3>
            {scoreboard.length === 0 ? (
              <p className="text-gray-400 text-sm">No teams yet</p>
            ) : (
              <div className="space-y-2">
                {scoreboard.slice(0, 10).map((entry) => (
                  <div key={entry.rank} className="flex justify-between items-center">
                    <div className="flex items-center gap-2">
                      <span className={`w-6 h-6 flex items-center justify-center rounded text-sm font-bold ${
                        entry.rank === 1 ? 'bg-yellow-500 text-black' :
                        entry.rank === 2 ? 'bg-gray-400 text-black' :
                        entry.rank === 3 ? 'bg-orange-600 text-white' :
                        'bg-gray-700 text-white'
                      }`}>
                        {entry.rank}
                      </span>
                      <span className="text-white text-sm">{entry.team_name}</span>
                    </div>
                    <span className="text-green-400 font-medium">{entry.score}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default CTFPanel;
