export const REGIONS = [
  { id: 'us-east-1', name: 'US East', api: 'https://api.mypurecloud.com', oauth: 'https://login.mypurecloud.com' },
  { id: 'us-east-2', name: 'US East 2 (Gov)', api: 'https://api.use2.us-gov-pure.cloud', oauth: 'https://login.use2.us-gov-pure.cloud' },
  { id: 'us-west-2', name: 'US West', api: 'https://api.usw2.pure.cloud', oauth: 'https://login.usw2.pure.cloud' },
  { id: 'eu-west-1', name: 'EU West (Ireland)', api: 'https://api.mypurecloud.ie', oauth: 'https://login.mypurecloud.ie' },
  { id: 'eu-central-1', name: 'EU Central (Frankfurt)', api: 'https://api.mypurecloud.de', oauth: 'https://login.mypurecloud.de' },
  { id: 'ap-southeast-1', name: 'AP Southeast 1 (Singapore)', api: 'https://api.mypurecloud.com.sg', oauth: 'https://login.mypurecloud.com.sg' },
  { id: 'ap-northeast-1', name: 'AP Northeast (Tokyo)', api: 'https://api.mypurecloud.jp', oauth: 'https://login.mypurecloud.jp' },
  { id: 'ap-southeast-2', name: 'AP Southeast 2 (Sydney)', api: 'https://api.mypurecloud.com.au', oauth: 'https://login.mypurecloud.com.au' },
];
export function trustedBaseUrl(value: string, kind: 'api' | 'oauth') {
  let parsed:URL;try{parsed=new URL(value);}catch{throw new Error('The endpoint must exactly match an official Genesys Cloud region URL.');}
  const region = REGIONS.find(r => (kind === 'api' ? r.api : r.oauth) === parsed.origin);
  if (!region || parsed.protocol!=='https:' || parsed.pathname !== '/' || parsed.search || parsed.hash || parsed.username || parsed.password || parsed.port) {
    throw new Error('The endpoint must exactly match an official Genesys Cloud region URL.');
  }
  return parsed.origin;
}
