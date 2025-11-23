import React, { useState, useEffect } from 'react';

function Dashboard({ apiUrl, token }) {
  const [metrics, setMetrics] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 30000); // Refresh every 30s
    return () => clearInterval(interval);
  }, []);

  const fetchData = async () => {
    try {
      const headers = {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      };

      // Fetch alerts
      const alertsRes = await fetch(`${apiUrl}/api/metrics/alerts`, { headers });
      if (alertsRes.ok) {
        setAlerts(await alertsRes.json());
      }

      // Fetch findings summary
      const summaryRes = await fetch(`${apiUrl}/api/findings/summary`, { headers });
      if (summaryRes.ok) {
        setSummary(await summaryRes.json());
      }

    } catch (error) {
      console.error('Failed to fetch dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="text-gray-400">Loading dashboard...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-white">Security Dashboard</h1>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <StatCard
          title="Total Findings"
          value={summary?.total || 0}
          color="blue"
        />
        <StatCard
          title="Critical"
          value={summary?.by_severity?.critical || 0}
          color="red"
        />
        <StatCard
          title="High"
          value={summary?.by_severity?.high || 0}
          color="orange"
        />
        <StatCard
          title="Active Alerts"
          value={alerts.length}
          color="yellow"
        />
      </div>

      {/* Alerts Section */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h2 className="text-lg font-semibold text-white mb-4">Recent Alerts</h2>
        {alerts.length === 0 ? (
          <p className="text-gray-400">No active alerts</p>
        ) : (
          <div className="space-y-3">
            {alerts.slice(0, 5).map((alert, index) => (
              <AlertItem key={index} alert={alert} />
            ))}
          </div>
        )}
      </div>

      {/* Findings by Severity */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h2 className="text-lg font-semibold text-white mb-4">Findings by Severity</h2>
        <div className="space-y-2">
          <SeverityBar label="Critical" count={summary?.by_severity?.critical || 0} total={summary?.total || 1} color="red" />
          <SeverityBar label="High" count={summary?.by_severity?.high || 0} total={summary?.total || 1} color="orange" />
          <SeverityBar label="Medium" count={summary?.by_severity?.medium || 0} total={summary?.total || 1} color="yellow" />
          <SeverityBar label="Low" count={summary?.by_severity?.low || 0} total={summary?.total || 1} color="green" />
          <SeverityBar label="Info" count={summary?.by_severity?.info || 0} total={summary?.total || 1} color="blue" />
        </div>
      </div>

      {/* Findings by Status */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h2 className="text-lg font-semibold text-white mb-4">Findings by Status</h2>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <StatusCard status="Open" count={summary?.by_status?.open || 0} />
          <StatusCard status="In Progress" count={summary?.by_status?.in_progress || 0} />
          <StatusCard status="Resolved" count={summary?.by_status?.resolved || 0} />
          <StatusCard status="False Positive" count={summary?.by_status?.false_positive || 0} />
          <StatusCard status="Accepted" count={summary?.by_status?.accepted_risk || 0} />
        </div>
      </div>
    </div>
  );
}

function StatCard({ title, value, color }) {
  const colorClasses = {
    blue: 'border-blue-500 text-blue-400',
    red: 'border-red-500 text-red-400',
    orange: 'border-orange-500 text-orange-400',
    yellow: 'border-yellow-500 text-yellow-400',
    green: 'border-green-500 text-green-400',
  };

  return (
    <div className={`bg-gray-800 rounded-lg p-4 border-l-4 ${colorClasses[color]}`}>
      <p className="text-gray-400 text-sm">{title}</p>
      <p className="text-2xl font-bold text-white">{value}</p>
    </div>
  );
}

function AlertItem({ alert }) {
  const severityColors = {
    critical: 'bg-red-900 border-red-700',
    warning: 'bg-yellow-900 border-yellow-700',
  };

  return (
    <div className={`p-3 rounded border ${severityColors[alert.severity] || 'bg-gray-700 border-gray-600'}`}>
      <div className="flex justify-between">
        <span className="font-medium text-white">{alert.type}</span>
        <span className="text-sm text-gray-400">{alert.timestamp}</span>
      </div>
      <p className="text-sm text-gray-300 mt-1">
        Value: {alert.value}% (threshold: {alert.threshold}%)
      </p>
    </div>
  );
}

function SeverityBar({ label, count, total, color }) {
  const percentage = total > 0 ? (count / total) * 100 : 0;

  const colorClasses = {
    red: 'bg-red-500',
    orange: 'bg-orange-500',
    yellow: 'bg-yellow-500',
    green: 'bg-green-500',
    blue: 'bg-blue-500',
  };

  return (
    <div className="flex items-center">
      <span className="w-20 text-sm text-gray-300">{label}</span>
      <div className="flex-1 mx-4 bg-gray-700 rounded-full h-4">
        <div
          className={`h-4 rounded-full ${colorClasses[color]}`}
          style={{ width: `${percentage}%` }}
        />
      </div>
      <span className="w-12 text-sm text-gray-300 text-right">{count}</span>
    </div>
  );
}

function StatusCard({ status, count }) {
  return (
    <div className="bg-gray-700 rounded p-3 text-center">
      <p className="text-sm text-gray-400">{status}</p>
      <p className="text-xl font-bold text-white">{count}</p>
    </div>
  );
}

export default Dashboard;
