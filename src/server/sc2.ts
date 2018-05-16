import * as user from './models/user.model';
import APIError from './helpers/APIError';
import * as HttpStatus from 'http-status';
import * as request from 'superagent';
import config from '../config/config';

const BASE_URL = `${config.steemconnectHost}/api`;
const SECRET = process.env.UTOPIAN_STEEMCONNECT_SECRET;

const SC2_SCOPES = [
  'vote',
  'comment',
  'delete_comment',
  'comment_options',
  'custom_json',
  'claim_reward_balance',
  'offline'
];

export interface AuthResponse {
  username: string;
  access_token: string;
  refresh_token: string;
  expires_in: number;
}

export interface SendOpts {
  method?: string;
  user?: any;
  data?: any;
  token?: any;
}

export async function send(endpoint: string, opts?: SendOpts) {
  if (!opts) opts = {};
  if (!opts.method) opts.method = 'POST';
  if (opts.user && !opts.user.sc2) throw new Error('User has no token');

  const token = opts.token ? opts.token
                            : (opts.user ? opts.user.sc2.token : null);
  const req = request(opts.method, BASE_URL + endpoint);
  if (opts.data) req.send(opts.data);
  if (token) req.set('Authorization', token);

  const res = await req;
  if (res.status !== 200) {
    throw new Error('Invalid status from API: '
                      + res.status + '\n' + res.body);
  }
  return res.body;
}

export async function getToken(code: string,
                                refresh = false): Promise<AuthResponse> {
  let field;
  if (refresh) {
    field = `refresh_token=${code}`;
  } else {
    field = `code=${code}`;
  }

  const scope = `scope=${encodeURIComponent(SC2_SCOPES.join(','))}`;
  const auth = `/oauth2/token?${field}&client_secret=${SECRET}&${scope}`;
  const data: AuthResponse = await send(auth);
  if (!(data.username
          && data.access_token
          && data.refresh_token
          && data.expires_in)) {
    throw new APIError('SC2 response missing required fields for authorization',
                        HttpStatus.INTERNAL_SERVER_ERROR, true);
  }

  {
    const profile = await send('/me', {
      token: data.access_token
    });
    for (const s of SC2_SCOPES) {
      if (!profile.scope.includes(s)) {
        const joined = SC2_SCOPES.join(',');
        throw new APIError(`Missing one of the required scopes: ${joined}`,
                            HttpStatus.BAD_REQUEST, true);
      }
    }
  }

  return data;
}
