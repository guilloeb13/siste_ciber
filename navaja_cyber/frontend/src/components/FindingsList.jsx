import React, { useState, useEffect } from 'react';

function FindingsList({ apiUrl, token }) {
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState({
    severity: '',
    status: '',
    source: '',
  });

  useEffect(() => {
    fetchFindings();
  }, [filter]);

  const fetchFindings = async () => {
    try {
      const params = new URLSearchParams();
      if (filter.severity) params.append('severity', filter.severity);
      if (filter.status) params.append('status', filter.status);
      if (filter.source) params.append('source', filter.source);

      const response = await fetch(`${apiUrl}/api/findings?${params}`, {
        headers: {
          'Authorization': `Bearer ${token}`,
        }
      });

      if (response.ok) {
        setFindings(await response.json());
      }
    } catch (error) {
      console.error('Failed to fetch findings:', error);
    } finally {
      setLoading(false);
    }
  };

  const updateFindingStatus = async (findingId, newStatus) => {
    try {
      const response = await fetch(`${apiUrl}/api/findings/${findingId}`, {
        method: 'PATCH',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ status: newStatus }),
      });

      if (response.ok) {
        fetchFindings();
      }
    } catch (error) {
      console.error('Failed to update finding:', error);
    }
  };

  const severityColor = (severity) => {
    const colors = {
      critical: 'bg-red-900 text-red-200',
      high: 'bg-orange-900 text-orange-200',
      medium: 'bg-yellow-900 text-yellow-200',
      low: 'bg-green-900 text-green-200',
      info: 'bg-blue-900 text-blue-200',
    };
    return colors[severity] || 'bg-gray-700 text-gray-200';
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="text-gray-400">Loading findings...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold text-white">Security Findings</h1>
        <span className="text-gray-400">{findings.length} findings</span>
      </div>

      {/* Filters */}
      <div className="bg-gray-800 rounded-lg p-4 flex gap-4">
        <select
          value={filter.severity}
          onChange={(e) => setFilter({ ...filter, severity: e.target.value })}
          className="bg-gray-700 text-white rounded px-3 py-2"
        >
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>

        <select
          value={filter.status}
          onChange={(e) => setFilter({ ...filter, status: e.target.value })}
          className="bg-gray-700 text-white rounded px-3 py-2"
        >
          <option value="">All Status</option>
          <option value="open">Open</option>
          <option value="in_progress">In Progress</option>
          <option value="resolved">Resolved</option>
          <option value="false_positive">False Positive</option>
        </select>

        <select
          value={filter.source}
          onChange={(e) => setFilter({ ...filter, source: e.target.value })}
          className="bg-gray-700 text-white rounded px-3 py-2"
        >
          <option value="">All Sources</option>
          <option value="bandit">Bandit</option>
          <option value="pip-audit">pip-audit</option>
          <option value="secrets">Secrets</option>
          <option value="semgrep">Semgrep</option>
        </select>
      </div>

      {/* Findings List */}
      <div className="space-y-4">
        {findings.length === 0 ? (
          <div className="bg-gray-800 rounded-lg p-6 text-center text-gray-400">
            No findings match your filters
          </div>
        ) : (
          findings.map((finding) => (
            <div key={finding.id} className="bg-gray-800 rounded-lg p-4">
              <div className="flex justify-between items-start">
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <span className={`px-2 py-1 rounded text-xs font-medium ${severityColor(finding.severity)}`}>
                      {finding.severity.toUpperCase()}
                    </span>
                    <span className="text-xs text-gray-500">{finding.source}</span>
                    {finding.rule_id && (
                      <span className="text-xs text-gray-500">{finding.rule_id}</span>
                    )}
                  </div>
                  <h3 className="text-lg font-medium text-white mt-2">{finding.title}</h3>
                  {finding.description && (
                    <p className="text-gray-400 mt-1 text-sm">{finding.description}</p>
                  )}
                  {finding.file_path && (
                    <p className="text-gray-500 mt-2 text-sm font-mono">
                      {finding.file_path}:{finding.line_number || '?'}
                    </p>
                  )}
                  {finding.recommendation && (
                    <div className="mt-3 bg-gray-700 p-3 rounded text-sm">
                      <span className="text-green-400 font-medium">Recommendation: </span>
                      <span className="text-gray-300">{finding.recommendation}</span>
                    </div>
                  )}
                </div>

                <div className="ml-4">
                  <select
                    value={finding.status}
                    onChange={(e) => updateFindingStatus(finding.id, e.target.value)}
                    className="bg-gray-700 text-white rounded px-2 py-1 text-sm"
                  >
                    <option value="open">Open</option>
                    <option value="in_progress">In Progress</option>
                    <option value="resolved">Resolved</option>
                    <option value="false_positive">False Positive</option>
                    <option value="accepted_risk">Accepted Risk</option>
                  </select>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

export default FindingsList;
