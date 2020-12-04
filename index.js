require('dotenv').config();

const crypto = require('crypto');
const axios = require('axios');
const urlencode = require('urlencode');
const constants = require('constants');

const qs = require('qs');

const { log: print } = console;

const {
  CLIENT_ID,
  CLIENT_SECRET,
  CODEF_API_HOST,
  PUBLIC_KEY,
  KCREDIT_ID,
  KCREDIT_PASSWORD,
} = process.env;

const TOKEN_URL = 'https://oauth.codef.io/oauth/token';

const instance = axios.create({
  baseURL: `https://${CODEF_API_HOST}`,
  timeout: 45_000,
  headers: {
    Accept: 'application/json',
    'Content-Type': 'application/json',
  },
});

function publicEncRSA(data) {
  const key = `-----BEGIN PUBLIC KEY-----\n${PUBLIC_KEY}\n-----END PUBLIC KEY-----`;
  const bufferToEncrypt = Buffer.from(data);
  const encryptedData = crypto
    .publicEncrypt(
      { key, padding: constants.RSA_PKCS1_PADDING },
      bufferToEncrypt,
    )
    .toString('base64');

  return encryptedData;
}

async function requestToken() {
  const authHeader = Buffer
    .from(`${CLIENT_ID}:${CLIENT_SECRET}`)
    .toString('base64');

  const { data } = await instance.post(
    TOKEN_URL,
    qs.stringify({
      grant_type: 'client_credentials',
      scope: 'read',
    }),
    {
      headers: {
        Accept: 'application/json',
        Authorization: `Basic ${authHeader}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    },
  );

  return data;
}

async function request(path, payload, token) {
  const body = JSON.stringify(payload);

  const { data } = await instance.post(path, urlencode.encode(body), {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });

  return data;
}

async function createAccessToken() {
  const data = await requestToken();
  print(data);

  const { access_token: accessToken } = data;

  return accessToken;
}

async function queryContracts(accessToken) {
  const data = await request('v1/kr/insurance/0001/credit4u/contract-info', {
    organization: '0001',
    id: KCREDIT_ID,
    password: publicEncRSA(KCREDIT_PASSWORD),
    type: '0',
    userName: '권상민',
    identity: '',
    telecom: '0',
    phoneNo: '010********',
    timeout: '160',
  }, accessToken);

  print(urlencode.decode(data));

  return data;
}

async function main() {
  const accessToken = await createAccessToken();
  await queryContracts(accessToken);
}

main();
