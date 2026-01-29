import React, { useState, useEffect } from 'react';
import { createClient } from '@supabase/supabase-js';
import { 
  Shield, 
  AlertTriangle, 
  Activity, 
  Eye,
  Search,
  Zap,
  Target,
  Skull
} from 'lucide-react';

// Initialize Supabase client
const supabase = createClient(
  import.meta.env.VITE_SUPABASE_URL || '',
  import.meta.env.VITE_SUPABASE_ANON_KEY || ''
);

const StatCard = ({ title, value, icon, trend, alert }) => (
  <div className={`p-6 border-2 rounded-lg bg-black/50 ${alert ? 'border-red-500 animate-pulse' : 'border-green-500'}`}>
    <div className="flex items-start justify-between mb-4">
      <div className={alert ? 'text-red-500' : 'text-green-500'}>
        {icon}
      </div>
      {trend && (
        <div className={`text-xs font-bold ${alert ? 'text-red-500' : 'text-green-600'}`}>
          {trend}
        </div>
      )}
    </div>
    <div className="text-sm text-gray-400 mb-1">{title}</div>
    <div className={`text-2xl font-bold ${alert ? 'text-red-500' : 'text-green-400'}`}>
      {value}
    </div>
  </div>
);

const SIEMLiteDashboard = () => {
  const [logs, setLogs] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState({
    totalEvents: 0,
    anomalyCount: 0,
    criticalAlerts: 0,
    topSources: []
  });
  const [selectedSeverity, setSelectedSeverity] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [timeRange, setTimeRange] = useState('1h');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchDashboardData();
    
    const subscription = supabase
      .channel('log_events')
      .on('postgres_changes', 
        { event: 'INSERT', schema: 'public', table: 'log_events' },
        payload => {
          setLogs(prev => [payload.new, ...prev].slice(0, 100));
          updateStats();
        }
      )
      .subscribe();

    return () => {
      subscription.unsubscribe();
    };
  }, [timeRange]);

  const fetchDashboardData = async () => {
    setLoading(true);
    try {
      const now = new Date();
      const timeRanges = {
        '15m': 15,
        '1h': 60,
        '6h': 360,
        '24h': 1440
      };
      const minutes = timeRanges[timeRange] || 60;
      const startTime = new Date(now - minutes * 60 * 1000).toISOString();

      const { data: logsData } = await supabase
        .from('log_events')
        .select('*')
        .gte('timestamp', startTime)
        .order('timestamp', { ascending: false })
        .limit(100);

      const { data: alertsData } = await supabase
        .from('alerts')
        .select('*')
        .gte('triggered_at', startTime)
        .order('triggered_at', { ascending: false });

      setLogs(logsData || []);
      setAlerts(alertsData || []);
      
      if (logsData) {
        const anomalies = logsData.filter(log => log.is_anomaly);
        const criticals = alertsData?.filter(a => a.severity === 'critical') || [];
        
        const sourceCounts = {};
        logsData.forEach(log => {
          sourceCounts[log.source] = (sourceCounts[log.source] || 0) + 1;
        });
        
        const topSources = Object.entries(sourceCounts)
          .sort((a, b) => b[1] - a[1])
          .slice(0, 5);

        setStats({
          totalEvents: logsData.length,
          anomalyCount: anomalies.length,
          criticalAlerts: criticals.length,
          topSources
        });
      }
    } catch (error) {
      console.error('Error fetching dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  const updateStats = async () => {
    const { data } = await supabase
      .from('log_events')
      .select('is_anomaly')
      .limit(100);
    
    if (data) {
      setStats(prev => ({
        ...prev,
        totalEvents: prev.totalEvents + 1,
        anomalyCount: prev.anomalyCount + (data[0]?.is_anomaly ? 1 : 0)
      }));
    }
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: 'from-red-500 to-red-700',
      high: 'from-orange-500 to-orange-700',
      medium: 'from-yellow-500 to-yellow-700',
      low: 'from-blue-500 to-blue-700',
      info: 'from-gray-500 to-gray-700'
    };
    return colors[severity] || colors.info;
  };

  const getSeverityIcon = (severity) => {
    if (severity === 'critical') return <Skull className="w-4 h-4" />;
    if (severity === 'high') return <AlertTriangle className="w-4 h-4" />;
    return <Shield className="w-4 h-4" />;
  };

  const filteredLogs = logs.filter(log => {
    const matchesSeverity = selectedSeverity === 'all' || log.severity === selectedSeverity;
    const matchesSearch = !searchTerm || 
      log.message.toLowerCase().includes(searchTerm.toLowerCase()) ||
      log.source.toLowerCase().includes(searchTerm.toLowerCase()) ||
      log.event_type.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesSeverity && matchesSearch;
  });

  return (
    <div className="min-h-screen bg-black text-green-400 font-mono">
      <div className="fixed inset-0 opacity-10">
        <div className="absolute inset-0" style={{
          backgroundImage: `
            linear-gradient(rgba(0, 255, 0, 0.1) 1px, transparent 1px),
            linear-gradient(90deg, rgba(0, 255, 0, 0.1) 1px, transparent 1px)
          `,
          backgroundSize: '50px 50px'
        }}></div>
      </div>

      <div className="fixed inset-0 pointer-events-none opacity-5">
        <div className="absolute inset-0 animate-scanline" style={{
          background: 'linear-gradient(transparent 50%, rgba(0, 255, 0, 0.1) 50%)',
          backgroundSize: '100% 4px'
        }}></div>
      </div>

      <div className="relative z-10">
        <header className="border-b-2 border-green-500 bg-black/90 backdrop-blur-sm sticky top-0 z-50">
          <div className="container mx-auto px-6 py-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4">
                <div className="relative">
                  <Shield className="w-12 h-12 text-green-500" strokeWidth={1.5} />
                  <div className="absolute inset-0 bg-green-500 blur-xl opacity-50"></div>
                </div>
                <div>
                  <h1 className="text-3xl font-bold tracking-wider text-green-400">
                    SIEM_LITE
                  </h1>
                  <p className="text-xs text-green-600">SECURITY EVENT MONITORING SYSTEM v1.0</p>
                </div>
              </div>
              
              <div className="flex items-center gap-4">
                <div className="flex items-center gap-2 px-4 py-2 border border-green-500 rounded bg-green-500/10">
                  <Activity className="w-4 h-4 animate-pulse" />
                  <span className="text-sm">LIVE</span>
                </div>
                <div className="text-sm text-green-600">
                  {new Date().toISOString().replace('T', ' ').substring(0, 19)}
                </div>
              </div>
            </div>
          </div>
        </header>

        <div className="container mx-auto px-6 py-8">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            <StatCard
              title="TOTAL EVENTS"
              value={stats.totalEvents.toLocaleString()}
              icon={<Eye className="w-6 h-6" />}
              trend="+12%"
            />
            <StatCard
              title="ANOMALIES DETECTED"
              value={stats.anomalyCount.toLocaleString()}
              icon={<Target className="w-6 h-6" />}
              trend={`${((stats.anomalyCount / stats.totalEvents) * 100 || 0).toFixed(1)}%`}
              alert={stats.anomalyCount > 0}
            />
            <StatCard
              title="CRITICAL ALERTS"
              value={stats.criticalAlerts.toLocaleString()}
              icon={<Skull className="w-6 h-6" />}
              alert={stats.criticalAlerts > 0}
            />
            <StatCard
              title="THREAT LEVEL"
              value={stats.anomalyCount > 10 ? "HIGH" : stats.anomalyCount > 5 ? "MEDIUM" : "LOW"}
              icon={<Zap className="w-6 h-6" />}
              alert={stats.anomalyCount > 10}
            />
          </div>

          {alerts.length > 0 && (
            <div className="mb-8 p-6 border-2 border-red-500 rounded-lg bg-red-500/5 animate-pulse-slow">
              <div className="flex items-center gap-3 mb-4">
                <AlertTriangle className="w-6 h-6 text-red-500" />
                <h2 className="text-xl font-bold text-red-500">ACTIVE ALERTS</h2>
              </div>
              <div className="space-y-3">
                {alerts.slice(0, 3).map(alert => (
                  <div key={alert.id} className="flex items-center justify-between p-3 bg-black/50 rounded border border-red-500/30">
                    <div className="flex items-center gap-3">
                      {getSeverityIcon(alert.severity)}
                      <div>
                        <div className="font-semibold text-red-400">{alert.title}</div>
                        <div className="text-xs text-red-600">{alert.description}</div>
                      </div>
                    </div>
                    <div className="text-xs text-red-600">
                      {new Date(alert.triggered_at).toLocaleTimeString()}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="flex flex-wrap gap-4 mb-6">
            <div className="flex-1 min-w-[300px]">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-green-600" />
                <input
                  type="text"
                  placeholder="Search logs..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full pl-12 pr-4 py-3 bg-black border-2 border-green-500 rounded text-green-400 placeholder-green-800 focus:outline-none focus:border-green-400 focus:shadow-lg focus:shadow-green-500/20"
                />
              </div>
            </div>

            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="px-4 py-3 bg-black border-2 border-green-500 rounded text-green-400 focus:outline-none focus:border-green-400 cursor-pointer"
            >
              <option value="all">ALL SEVERITY</option>
              <option value="critical">CRITICAL</option>
              <option value="high">HIGH</option>
              <option value="medium">MEDIUM</option>
              <option value="low">LOW</option>
              <option value="info">INFO</option>
            </select>

            <select
              value={timeRange}
              onChange={(e) => setTimeRange(e.target.value)}
              className="px-4 py-3 bg-black border-2 border-green-500 rounded text-green-400 focus:outline-none focus:border-green-400 cursor-pointer"
            >
              <option value="15m">LAST 15 MIN</option>
              <option value="1h">LAST HOUR</option>
              <option value="6h">LAST 6 HOURS</option>
              <option value="24h">LAST 24 HOURS</option>
            </select>
          </div>

          <div className="border-2 border-green-500 rounded-lg overflow-hidden bg-black/50">
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-green-500 text-black">
                  <tr>
                    <th className="px-4 py-3 text-left font-bold">TIMESTAMP</th>
                    <th className="px-4 py-3 text-left font-bold">SEVERITY</th>
                    <th className="px-4 py-3 text-left font-bold">SOURCE</th>
                    <th className="px-4 py-3 text-left font-bold">EVENT TYPE</th>
                    <th className="px-4 py-3 text-left font-bold">MESSAGE</th>
                    <th className="px-4 py-3 text-left font-bold">ANOMALY</th>
                  </tr>
                </thead>
                <tbody>
                  {loading ? (
                    <tr>
                      <td colSpan="6" className="px-4 py-8 text-center text-green-600">
                        <Activity className="w-6 h-6 animate-spin mx-auto mb-2" />
                        LOADING EVENTS...
                      </td>
                    </tr>
                  ) : filteredLogs.length === 0 ? (
                    <tr>
                      <td colSpan="6" className="px-4 py-8 text-center text-green-600">
                        NO EVENTS FOUND
                      </td>
                    </tr>
                  ) : (
                    filteredLogs.map((log) => (
                      <tr 
                        key={log.id} 
                        className={`border-t border-green-900 hover:bg-green-500/10 transition-colors ${
                          log.is_anomaly ? 'bg-red-500/5' : ''
                        }`}
                      >
                        <td className="px-4 py-3 text-sm text-green-600">
                          {new Date(log.timestamp).toLocaleString()}
                        </td>
                        <td className="px-4 py-3">
                          <span className={`px-2 py-1 rounded text-xs font-bold text-white bg-gradient-to-r ${getSeverityColor(log.severity)}`}>
                            {log.severity.toUpperCase()}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-sm">{log.source}</td>
                        <td className="px-4 py-3 text-sm text-green-300">{log.event_type}</td>
                        <td className="px-4 py-3 text-sm max-w-md truncate" title={log.message}>
                          {log.message}
                        </td>
                        <td className="px-4 py-3 text-center">
                          {log.is_anomaly && (
                            <div className="flex items-center justify-center gap-1">
                              <Target className="w-4 h-4 text-red-500" />
                              <span className="text-xs text-red-500 font-bold">
                                {(log.anomaly_score * 100).toFixed(0)}%
                              </span>
                            </div>
                          )}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>

          <div className="mt-8 pt-6 border-t border-green-900 text-center text-xs text-green-800">
            <p>SIEM LITE v1.0</p></div>
        </div>
      </div>
    </div>
  );
}

export default SIEMLiteDashboard;