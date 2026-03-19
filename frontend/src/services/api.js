import axios from 'axios';

const API = axios.create({ baseURL: '/api' });

export const fetchStats      = ()        => API.get('/stats/');
export const fetchAlerts     = (params)  => API.get('/alerts/', { params });
export const fetchAlert      = (id)      => API.get(`/alerts/${id}/`);
export const updateStatus    = (id, s)   => API.patch(`/alerts/${id}/status/`, { status: s });
export const predict         = (data)    => API.post('/predict/', data);
export const simulate        = ()        => API.post('/simulate/');
export const fetchBlockchain = ()        => API.get('/blockchain/');
export const verifyChain     = ()        => API.get('/blockchain/verify/');

export default API;
