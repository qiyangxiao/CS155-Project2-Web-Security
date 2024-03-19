import express from 'express';
import sqlite from 'sqlite';

import { asyncMiddleware } from './utils/asyncMiddleware';
import sleep from './utils/sleep';
import { generateRandomness, HMAC, KDF, checkPassword } from './utils/crypto';

const router = express.Router();
const dbPromise = sqlite.open('./db/database.sqlite');

/* Charlie and Delta defense: use HMAC to check whether cookie is tampered */
const secretKey =  generateRandomness();

function setHMAC(session) {
  const data = JSON.stringify(session.loggedIn) + JSON.stringify(session.account);
  const hmac = HMAC(secretKey, data);
  return hmac;
};

function checkHMAC(session) {
  const data = JSON.stringify(session.loggedIn) + JSON.stringify(session.account);
  const _hmac = HMAC(secretKey, data);
  const hmac = session.hmac;
  if(_hmac === hmac) {
    return true;
  }
  return false;
};

/* Gamma defense: use random sleep time to avoid timing attack */
function arbitaryAwaitTime(min, max) {
  const num = Math.random() * (max - min) + min;
  return Math.ceil(num);
}



function render(req, res, next, page, title, errorMsg = false, result = null, nonceToken = null) {
  res.render(
    'layout/template', {
      page,
      title,
      loggedIn: req.session.loggedIn,
      account: req.session.account,
      errorMsg,
      result,
      /* Foxtrot defense: add nonceToken to the response(mind the initialization at params) */
      nonceToken,
    }
  );
}


router.get('/', (req, res, next) => {
  render(req, res, next, 'index', 'Bitbar Home');
});


router.post('/set_profile', asyncMiddleware(async (req, res, next) => {

  /* Charlie and Delta defense: check the cookie when setting profile */
  if(!checkHMAC(req.session)) {
    req.session.loggedIn = false;
    req.session.account = {};
    req.session.hmac = setHMAC(req.session);
    render(req, res, next, 'login/form', 'Login', 'You must be logged in to use this feature!');
    return;
  };
  
  req.session.account.profile = req.body.new_profile;
  console.log(req.body.new_profile);
  const db = await dbPromise;
  //const query = `UPDATE Users SET profile = ? WHERE username = "${req.session.account.username}";`;
  //const result = await db.run(query, req.body.new_profile);
  
  /* Echo defense: optimize the SQL query method by parameterized query */
  const query = `UPDATE Users SET profile = ? WHERE username = ?;`;
  const result = await db.run(query, [req.body.new_profile, req.session.account.username]);
  
  /* Charlie and Delta defense: update HMAC after setting profile */
  req.session.hmac = setHMAC(req.session);
  
  render(req, res, next, 'index', 'Bitbar Home');

}));


router.get('/login', (req, res, next) => {
  render(req, res, next, 'login/form', 'Login');
});


router.get('/get_login', asyncMiddleware(async (req, res, next) => {
  const db = await dbPromise;
  const query = `SELECT * FROM Users WHERE username == "${req.query.username}";`;
  const result = await db.get(query);
  if(result) { // if this username actually exists
    if(checkPassword(req.query.password, result)) { // if password is valid
      //await sleep(2000);
      
      /* Gamma defense: generate a random await time to avoid timing */
      const abTime = arbitaryAwaitTime(500, 1000);
      await sleep(abTime);
      
      req.session.loggedIn = true;
      req.session.account = result;
      
      /* Charlie and Delta defense: update HMAC after login */
      req.session.hmac = setHMAC(req.session);
      
      render(req, res, next, 'login/success', 'Bitbar Home');
      return;
    }
  }
  
  /* Gamma defense: generate a random await time to avoid timing */
  const abTime = arbitaryAwaitTime(500, 1000);
  await sleep(abTime);
  
  render(req, res, next, 'login/form', 'Login', 'This username and password combination does not exist!');
}));


router.get('/register', (req, res, next) => {
  render(req, res, next, 'register/form', 'Register');
});


router.post('/post_register', asyncMiddleware(async (req, res, next) => {
  const db = await dbPromise;
  let query = `SELECT * FROM Users WHERE username == "${req.body.username}";`;
  let result = await db.get(query);
  if(result) { // query returns results
    if(result.username === req.body.username) { // if username exists
      render(req, res, next, 'register/form', 'Register', 'This username already exists!');
      return;
    }
  }
  const salt = generateRandomness();
  const hashedPassword = KDF(req.body.password, salt);
  console.log(hashedPassword);
  console.log(salt);
  query = `INSERT INTO Users(username, hashedPassword, salt, profile, bitbars) VALUES(?, ?, ?, ?, ?)`;
  await db.run(query, [req.body.username, hashedPassword, salt, '', 100]);
  req.session.loggedIn = true;
  req.session.account = {
    username: req.body.username,
    hashedPassword,
    salt,
    profile: '',
    bitbars: 100,
  };
  
  /* Charlie and Delta defense: update HMAC after register */
  req.session.hmac = setHMAC(req.session);
  
  render(req, res, next,'register/success', 'Bitbar Home');
}));


router.get('/close', asyncMiddleware(async (req, res, next) => {
  if(req.session.loggedIn == false) {
    render(req, res, next, 'login/form', 'Login', 'You must be logged in to use this feature!');
    return;
  };
  const db = await dbPromise;
  //const query = `DELETE FROM Users WHERE username == "${req.session.account.username}";`;
  //await db.get(query);
  
  /* Echo defense: optimize the SQL query method by parameterized query */
  const query = `DELETE FROM Users WHERE username == ?;`;
  await db.get(query, req.session.account.username);
  
  req.session.loggedIn = false;
  req.session.account = {};
  
  /* Charlie and Delta defense: update HMAC after close */
  req.session.hmac = setHMAC(req.session);
  
  render(req, res, next, 'index', 'Bitbar Home', 'Deleted account successfully!');
}));


router.get('/logout', (req, res, next) => {
  req.session.loggedIn = false;
  req.session.account = {};
  
  /* Charlie and Delta defense: update HMAC after logout */
  req.session.hmac = setHMAC(req.session);
  
  render(req, res, next, 'index', 'Bitbar Home', 'Logged out successfully!');
});


router.get('/profile', asyncMiddleware(async (req, res, next) => {
  /* Charlie and Delta defense: unset the session if HMAC doesn't equal */
  if(!checkHMAC(req.session)) {
    req.session.loggedIn = false;
    req.session.account = {};
    req.session.hmac = setHMAC(req.session);
  };
  
  if(req.session.loggedIn == false) {
    render(req, res, next, 'login/form', 'Login', 'You must be logged in to use this feature!');
    return;
  };
    
  /* Alpha defense: decode the input username and test for filtering */
  const decodedUsername = decodeURIComponent(req.query.username).toLowerCase();
  const invaildChars = /[<>; '``\${}().\/]/g;
  if(invaildChars.test(decodedUsername)) {
    render(req, res, next, 'profile/view', 'View Profile', 'Invalid user name input!', req.session.account);
    return;
  };

  /* Foxtrot defense: add CSP request header and generate a random nonce */
  const nonceToken = generateRandomness();
  res.setHeader('Content-Security-Policy', `script-src 'nonce-${nonceToken}' 'unsafe-eval'`);
  
  if(req.query.username != null) { // if visitor makes a search query
    const db = await dbPromise;
    const query = `SELECT * FROM Users WHERE username == "${req.query.username}";`;
    let result;
    try {
      result = await db.get(query);
    } catch(err) {
      result = false;
    }
    if(result) { // if user exists
      render(req, res, next, 'profile/view', 'View Profile', false, result, nonceToken);
    }
    else { // user does not exist
      render(req, res, next, 'profile/view', 'View Profile', `${req.query.username} does not exist!`, req.session.account);
    }
  } else { // visitor did not make query, show them their own profile
    render(req, res, next, 'profile/view', 'View Profile', false, req.session.account, nonceToken);
  }
}));


router.get('/transfer', (req, res, next) => {
  /* Charlie and Delta defense: unset the session if HMAC doesn't equal */
  if(!checkHMAC(req.session)) {
    req.session.loggedIn = false;
    req.session.account = {};
    req.session.hmac = setHMAC(req.session);
  };
  
  if(req.session.loggedIn == false) {
    render(req, res, next, 'login/form', 'Login', 'You must be logged in to use this feature!');
    return;
  };
  
  /* Bravo defense: generate the CSRF token and store to the transfer from */
  const csrfToken = generateRandomness();
  req.session.csrfToken = csrfToken;
  
  render(req, res, next, 'transfer/form', 'Transfer Bitbars', false, {receiver:null, amount:null, csrfToken:csrfToken});
});


router.post('/post_transfer', asyncMiddleware(async(req, res, next) => {
  /* Charlie and Delta defense: unset the session if HMAC doesn't equal */
  if(!checkHMAC(req.session)) {
    req.session.loggedIn = false;
    req.session.account = {};
    req.session.hmac = setHMAC(req.session);
  };
  
  if(req.session.loggedIn == false) {
    render(req, res, next, 'login/form', 'Login', 'You must be logged in to use this feature!');
    return;
  };

  if(req.body.destination_username === req.session.account.username) {
    render(req, res, next, 'transfer/form', 'Transfer Bitbars', 'You cannot send money to yourself!', {receiver:null, amount:null});
    return;
  }

  /* Bravo defense: check the CSRF token with the server session */
  if(!req.session.csrfToken || req.body.csrf_token != req.session.csrfToken) {
    req.session.loggedIn = false;
    req.session.account = {};
    req.session.csrfToken = false;
    render(req, res, next, 'index', 'Bitbar Home', 'Logged out successfully!');
    return;
  };
  
  const db = await dbPromise;
  //let query = `SELECT * FROM Users WHERE username == "${req.body.destination_username}";`;
  //const receiver = await db.get(query);
  
  /* Echo defense: optimize the SQL query by parameterized query*/
  let query = `SELECT * FROM Users WHERE username == ?;`;
  const receiver = await db.get(query, req.body.destination_username);
  
  if(receiver) { // if user exists
    const amount = parseInt(req.body.quantity);
    if(Number.isNaN(amount) || amount > req.session.account.bitbars || amount < 1) {
      render(req, res, next, 'transfer/form', 'Transfer Bitbars', 'Invalid transfer amount!', {receiver:null, amount:null});
      return;
    }

    req.session.account.bitbars -= amount;
    //query = `UPDATE Users SET bitbars = "${req.session.account.bitbars}" WHERE username == "${req.session.account.username}";`;
    //await db.exec(query);
    const receiverNewBal = receiver.bitbars + amount;
    //query = `UPDATE Users SET bitbars = "${receiverNewBal}" WHERE username == "${receiver.username}";`;
    //await db.exec(query);
    
    /* Echo defense: optimize the SQL query by parameterized query*/
    query = `UPDATE Users SET bitbars = ? WHERE username == ?;`;
    await db.exec(query, [req.session.account.bitbars, req.session.account.username]);
    query = `UPDATE Users SET bitbars = ? WHERE username == ?;`;
    await db.exec(query, [receiverNewBal, receiver.username]);
	
    /* Charlie and Delta defense: update hmac after transfer */
    req.session.hmac = setHMAC(req.session);
    
    render(req, res, next, 'transfer/success', 'Transfer Complete', false, {receiver, amount});
  } else { // user does not exist
    let q = req.body.destination_username;
    if (q == null) q = '';

    let oldQ;
    while (q !== oldQ) {
      oldQ = q;
      q = q.replace(/script|SCRIPT|img|IMG/g, '');
    }
    render(req, res, next, 'transfer/form', 'Transfer Bitbars', `User ${q} does not exist!`, {receiver:null, amount:null});
  }
}));


router.get('/steal_cookie', (req, res, next) => {
  let stolenCookie = req.query.cookie;
  console.log('\n\n' + stolenCookie + '\n\n');
  render(req, res, next, 'theft/view_stolen_cookie', 'Cookie Stolen!', false, stolenCookie);
});

router.get('/steal_password', (req, res, next) => {
  let password = req.query.password;
  let timeElapsed = req.query.timeElapsed;
  console.log(`\n\nPassword: ${req.query.password}, time elapsed: ${req.query.timeElapsed}\n\n`);
  res.end();
});


module.exports = router;
