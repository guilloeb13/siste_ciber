import React, { useState, useEffect } from 'react';

function AgentsList({ apiUrl, token }) {
  const [agents, setAgents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedAgent, setSelectedAgent] = useState(null);
  const [metrics, setMetrics] = useState(null);

  useEffect(() => {
    fetchAgents();
    const interval = setInterval(fetchAgents, 30000);
    return () => clearInterval(interval);
  }, []);

  const fetchAgents = async () => {
    try {
      const response = await fetch(`${apiUrl}/api/agents`, {
        headers: {
          'Authorization': `Bearer ${token}`,
        }
      });

      if (response.ok) {
        setAgents(await response.json());
      }
    } catch (error) {
      console.error('Failed to fetch agents:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchAgentMetrics = async (agentId) => {
    try {
      const response = await fetch(`${apiUrl}/api/metrics/latest/${agentId}`, {
        headers: {
          'Authorization': `Bearer ${token}`,
        }
      });

      if (response.ok) {
        setMetrics(await response.json());
      }
    } catch (error) {
      console.error('Failed to fetch metrics:', error);
    }
  };

  const handleAgentClick = (agent) => {
    setSelectedAgent(agent);
    fetchAgentMetrics(agent.id);
  };

  const statusColor = (status) => {
    const colors = {
      active: 'bg-green-500',
      inactive: 'bg-gray-500',
      disconnected: 'bg-red-500',
      maintenance: 'bg-yellow-500',
    };
    return colors[status] || 'bg-gray-500';
  };

  const formatLastSeen = (timestamp) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = Math.floor((now - date) / 1000);

    if (diff < 60) return 'Just now';
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return date.toLocaleDateString();
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="text-gray-400">Loading agents...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold text-white">Monitoring Agents</h1>
        <span className="text-gray-400">{agents.length} agents</span>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Agents List */}
        <div className="lg:col-span-2 space-y-4">
          {agents.length === 0 ? (
            <div className="bg-gray-800 rounded-lg p-6 text-center text-gray-400">
              No agents registered. Use the agent registration command to add agents.
            </div>
          ) : (
            agents.map((agent) => (
              <div
                key={agent.id}
                onClick={() => handleAgentClick(agent)}
                className={`bg-gray-800 rounded-lg p-4 cursor-pointer hover:bg-gray-750 transition ${
                  selectedAgent?.id === agent.id ? 'ring-2 ring-green-500' : ''
                }`}
              >
                <div className="flex justify-between items-start">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className={`w-3 h-3 rounded-full ${statusColor(agent.status)}`} />
                      <h3 className="text-lg font-medium text-white">{agent.name}</h3>
                    </div>
                    <p className="text-gray-400 mt-1">{agent.hostname}</p>
                    <div className="flex gap-4 mt-2 text-sm text-gray-500">
                      <span>{agent.ip_address}</span>
                      <span>{agent.os_type}</span>
                    </div>
                  </div>
                  <div className="text-right">
                    <span className="text-sm text-gray-400">
                      {formatLastSeen(agent.last_seen)}
                    </span>
                    {agent.tags && agent.tags.length > 0 && (
                      <div className="mt-2 flex gap-1 justify-end">
                        {agent.tags.map((tag, i) => (
                          <span key={i} className="bg-gray-700 text-gray-300 px-2 py-1 rounded text-xs">
                            {tag}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            ))
          )}
        </div>

        {/* Agent Details */}
        <div className="bg-gray-800 rounded-lg p-4">
          <h3 className="text-md font-semibold text-white mb-4">Agent Details</h3>

          {!selectedAgent ? (
            <p className="text-gray-400 text-sm">Select an agent to view details</p>
          ) : (
            <div className="space-y-4">
              <div>
                <label className="text-sm text-gray-500">ID</label>
                <p className="text-white font-mono text-sm">{selectedAgent.id}</p>
              </div>
              <div>
                <label className="text-sm text-gray-500">Status</label>
                <p className="text-white capitalize">{selectedAgent.status}</p>
              </div>
              <div>
                <label className="text-sm text-gray-500">OS</label>
                <p className="text-white">{selectedAgent.os_type}</p>
              </div>

              {/* Metrics */}
              {metrics && metrics.metrics && (
                <div className="pt-4 border-t border-gray-700">
                  <h4 className="text-sm font-semibold text-white mb-3">Latest Metrics</h4>
                  <div className="space-y-2">
                    {metrics.metrics.cpu && (
                      <MetricBar
                        label="CPU"
                        value={metrics.metrics.cpu.value}
                        max={100}
                        unit="%"
                      />
                    )}
                    {metrics.metrics.memory && (
                      <MetricBar
                        label="Memory"
                        value={metrics.metrics.memory.value}
                        max={100}
                        unit="%"
                      />
                    )}
                    {metrics.metrics.disk && (
                      <MetricBar
                        label="Disk"
                        value={metrics.metrics.disk.value}
                        max={100}
                        unit="%"
                      />
                    )}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function MetricBar({ label, value, max, unit }) {
  const percentage = (value / max) * 100;
  const color = percentage > 90 ? 'bg-red-500' : percentage > 70 ? 'bg-yellow-500' : 'bg-green-500';

  return (
    <div>
      <div className="flex justify-between text-sm mb-1">
        <span className="text-gray-400">{label}</span>
        <span className="text-white">{value.toFixed(1)}{unit}</span>
      </div>
      <div className="bg-gray-700 rounded-full h-2">
        <div
          className={`h-2 rounded-full ${color}`}
          style={{ width: `${percentage}%` }}
        />
      </div>
    </div>
  );
}

export default AgentsList;
