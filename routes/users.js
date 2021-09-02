var express = require('express');
var router = express.Router();
const models = require("../models");
const crypto = require("crypto");
const request = require('request')
const PythonShell = require('python-shell');
const { resolve } = require('path');
const { Sequelize } = require('../models');
const { default: swal } = require('sweetalert');
require('date-utils');

// Node.js program to demonstrate the      
// crypto.createDecipheriv() method 

// Difining algorithm 
const algorithm = 'aes-256-cbc';

/* GET users listing. */
// 회원가입 GET
router.get('/signup', function (req, res, next) {
  res.render("user/signup");
});

// 회원가입 POST
router.post("/signup", function (req, res, next) {
  let body = req.body;

  let password = body.password;
  let salt = Math.round((new Date().valueOf() * Math.random())) + "";
  let hashPassword = crypto.createHash("sha512").update(password + salt).digest("hex");

  let accessKey = body.accessKey;
  let secretKey = body.secretKey;

  // Defining key 
  const key = crypto.createHash("sha256").update(password + salt).digest('base64').substr(0, 32);

  // Defining iv 
  const iv = crypto.randomBytes(16);

  // An encrypt function 
  function encrypt(text) {

    console.log(key);

    // Creating Cipheriv with its parameter 
    let cipher =
      crypto.createCipheriv(algorithm, Buffer.from(key), iv);

    // Updating text 
    let encrypted = cipher.update(text);

    // Using concatenation 
    encrypted = Buffer.concat([encrypted, cipher.final()]);

    // Returning iv and encrypted data 
    return {
      iv: iv.toString('hex'),
      encryptedData: encrypted.toString('hex')
    };
  }

  var cipherAccessKey = encrypt(accessKey);
  var cipherSecretKey = encrypt(secretKey);

  console.log(JSON.stringify(cipherAccessKey))
  console.log(JSON.stringify(cipherSecretKey))

  models.user.create({
    email: body.email,
    password: hashPassword,
    accessKey: JSON.stringify(cipherAccessKey),
    secretKey: JSON.stringify(cipherSecretKey),
    key: key,
    salt: salt
  })
    .then(result => {
      console.log("회원가입 성공");
      //res.redirect("/users/login");
      res.render("user/login", { email: req.cookies['user'], flag1: "회원가입 성공" })
    })
    .catch(err => {
      console.log(err);
      res.render("user/signup", { email: req.cookies['user'], flag1: "회원가입 실패" })
    })
});

// 로그인 GET
router.get('/login', function (req, res, next) {
  //let session = req.session;
  console.log(req.cookies['user']);
  res.render("user/login", { email: req.cookies['user'] });
});

// 로그인 POST
router.post("/login", async function (req, res, next) {
  let body = req.body;

  let result = await models.user.findOne({
    where: {
      email: body.email
    }
  });

  console.log(result);
  if (result == null) {
    res.render("user/login", { email: req.cookies['user'], flag3: "존재하지 않는 아이디입니다." })
  } else {

    let dbPassword = result.dataValues.password;
    let inputPassword = body.password;
    let salt = result.dataValues.salt;
    let hashPassword = crypto.createHash("sha512").update(inputPassword + salt).digest("hex");

    if (dbPassword === hashPassword) {
      console.log("비밀번호 일치");
      // 세션 설정
      //req.session.email = body.email;
      res.cookie("user", body.email, {
        expires: new Date(Date.now() + 86400000), // 1일로 설정
        httpOnly: true
      });
      //res.redirect("/");
      res.render("index", { email: req.cookies['user'], flag: "로그인 성공" })
    }
    else {
      console.log("비밀번호 불일치");
      //res.redirect("/users/login");
      res.render("user/login", { email: req.cookies['user'], flag2: "로그인 실패" })
    }
  }
});

// coinGetAccessToken GET
router.get('/coinGetAccessToken', function (req, res, next) {
  res.render("user/coinGetAccessToken");
});

// coinGetAccessToken POST
router.post("/coinGetAccessToken", async function (req, res) {
  //let clientId = req.body.clientId
  //let clientSecret = req.body.clientSecret
  try {
    let email = req.cookies["user"];

    let result = await models.user.findOne({
      where: {
        email: email
      }
    });

    let dbKey = result.dataValues.key;
    let key = req.body.key;
    let salt = result.dataValues.salt;
    let hashKey = crypto.createHash("sha256").update(key + salt).digest('base64').substr(0, 32);

    if (dbKey == hashKey) {
      console.log("비밀번호 일치");
      console.log(JSON.parse(result.dataValues.accessKey))
      console.log(JSON.parse(result.dataValues.secretKey))

      // A decrypt function 
      function decrypt(text) {
        let iv = Buffer.from(text.iv, 'hex');
        let encryptedText =
          Buffer.from(text.encryptedData, 'hex');

        // Creating Decipher 
        let decipher = crypto.createDecipheriv(algorithm, Buffer.from(hashKey), iv);

        // Updating encrypted text 
        let decrypted = decipher.update(encryptedText);
        decrypted = Buffer.concat([decrypted, decipher.final()]);

        // returns data after decryption 
        return decrypted.toString();
      }


      let decipherAccessKey = decrypt(JSON.parse(result.dataValues.accessKey))
      let decipherSecretKey = decrypt(JSON.parse(result.dataValues.secretKey))

      console.log(decipherAccessKey)
      console.log(decipherSecretKey)

      var option = {
        url: 'https://api.korbit.co.kr/v1/oauth2/access_token',
        method: 'POST',
        qs: {
          client_id: decipherAccessKey,
          client_secret: decipherSecretKey,
          grant_type: 'client_credentials'
        }
      };
      request(option, function (error, response, body) {
        console.log(body);
        //console.log(JSON.stringify(response));
        var tmp = JSON.parse(body);
        console.log(tmp.access_token);
        // models.user.update(
        //   { coinGetAccessToken: tmp.access_token },
        //   { where: { email: req.body.email } }
        // )
        res.cookie("coinGetAccessToken", tmp.access_token, {
          expires: new Date(Date.now() + 3000000), // 1일로 설정함
          httpOnly: true
        });
        //res.redirect("/")
        res.render('user/myinfo', { email: req.cookies['user'], flag: 1 });
      });
    } else {
      console.log("비밀번호 불일치");
      res.render("user/coinGetAccessToken", { email: req.cookies['user'], flag: "비밀번호 불일치" })
    }

  }
  catch (e) {
    console.log('Catch an error: ', e)
  }
})

// wonGetAccessToken GET
router.get('/wonGetAccessToken', function (req, res, next) {

  var authCode = req.query.code;
  var email = req.cookies["user"];
  console.log(authCode);
  console.log(email);

  var option = {
    method: "POST",
    url: "https://testapi.openbanking.or.kr/oauth/2.0/token",
    headers: "",
    form: {
      code: authCode,
      client_id: '',
      client_secret: '',
      redirect_uri: 'http://localhost:3000/users/wonGetAccessToken',
      grant_type: 'authorization_code'
    }
  }
  request(option, function (error, response, body) {
    console.log(body);
    var accessRequestResult = JSON.parse(body);

    models.user.update(
      { cash3leggedToken: accessRequestResult.access_token },
      { where: { email: email } }
    )

    models.user.update(
      { cashGetRefreshToken: accessRequestResult.refresh_token },
      { where: { email: email } }
    )

    models.user.update(
      { userSeqNo: accessRequestResult.user_seq_no },
      { where: { email: email } }
    )
  });

  var option2 = {
    method: "POST",
    url: "https://testapi.openbanking.or.kr/oauth/2.0/token",
    headers: "",
    form: {
      client_id: '',
      client_secret: '',
      scope: 'oob',
      grant_type: 'client_credentials'
    }
  }
  request(option2, function (error, response, body) {
    console.log(body);
    var accessRequestResult = JSON.parse(body);

    models.user.update(
      { cash2leggedToken: accessRequestResult.access_token },
      { where: { email: email } }
    )
  });

  res.render('user/myinfo', { email: req.cookies['user'], flag: 1 });
  // res.render('user/resultChild',{data : accessRequestResult})
});

// wonGetAccessTokenCheck POST
router.post("/wonGetAccessTokenCheck", function (req, res) {

  var email = req.cookies["user"]
  if (email == undefined) {
    res.send("1");
  } else {
    if (1 == 0) {
      //if (access_token == undefined) {
      res.send("2");
    } else {
      res.send("3");
    }
  }
});

// payKor GET
router.get('/payKor', function (req, res, next) {
  res.render("user/payKor");
});

// payKor2 GET
router.get('/payKor2', function (req, res, next) {
  res.render("user/payKor2");
});

// payCoin GET
router.get('/payCoin', function (req, res, next) {
  res.render("user/payCoin");
});

// payCoin2 GET
router.get('/payCoin2', function (req, res, next) {
  res.render("user/payCoin2");
});

// lookupPayCoin GET
router.get('/lookupPayCoin', function (req, res, next) {
  res.render("user/lookupPayCoin");
});

// cancelCoin2 GET
router.get('/cancelCoin2', function (req, res, next) {
  res.render("user/cancelCoin2");
});

// sellCoin GET
router.get('/sellCoin', function (req, res, next) {
  res.render("user/sellCoin");
});

// buyCoin GET
router.get('/buyCoin', function (req, res, next) {
  res.render("user/buyCoin");
});

// lookupSellOrBuyCoin GET
router.get('/lookupSellOrBuyCoin', function (req, res, next) {
  res.render("user/lookupSellOrBuyCoin");
});

// cancelSellOrBuyCoin GET
router.get('/cancelSellOrBuyCoin', function (req, res, next) {
  res.render("user/cancelSellOrBuyCoin");
});

// 로그아웃
router.get("/logout", function (req, res, next) {
  //req.session.destroy();
  res.clearCookie('user');
  res.clearCookie('coinGetAccessToken');
  res.render("user/login");
});

// aboutPayHelper
router.get("/aboutPayHelper", function (req, res, next) {
  res.render("user/aboutPayHelper", { email: req.cookies['user'] });
});

// 조회
router.get("/lookup", function (req, res, next) {
  res.render("user/lookup", { email: req.cookies['user'] });
});

// 환전
router.get("/exchange", function (req, res, next) {
  res.render("user/exchange", { email: req.cookies['user'] });
});

// 결제
router.get("/payment", function (req, res, next) {
  res.render("user/payment", { email: req.cookies['user'] });
});

// myinfo GET
router.get("/myinfo", function (req, res, next) {
  res.render("user/myinfo", { email: req.cookies['user'] });
});

// myinfo POST




router.post('/ZIL', function (req, res) {
  var option = {
    mode: 'text',
    pythonPath: 'python',
    pythonOptions: ['-u'],
    scriptPath: '',
    args: ['value1', 'value2', 'value3']
  }

  PythonShell.PythonShell.run('ZIL.py', option, function (err, results) {
    if (err) throw err;
    console.log(parseInt(results));
    console.log(results);
    result = parseInt(results)
    res.json(result)
  })

})



router.post('/TRX', function (req, res) {
  var option = {
    mode: 'text',
    pythonPath: 'python',
    pythonOptions: ['-u'],
    scriptPath: '',
    args: ['value1', 'value2', 'value3']
  }

  PythonShell.PythonShell.run('TRX.py', option, function (err, results) {
    if (err) throw err;
    console.log(parseInt(results));
    console.log(results);
    result = parseInt(results)
    res.json(result)
  })

})

//암호화폐 조회
router.post('/lookup_coin', function (req, res) {
  var access_token = req.cookies["coinGetAccessToken"];
  var email = req.cookies["user"];

  if (email == undefined) {
    res.send("1");
  } else {
    if (access_token == undefined) {
      res.send("2");
    } else {
      var option = {
        url: 'https://api.korbit.co.kr/v1/user/balances',
        headers: {
          Authorization: 'Bearer ' + access_token
        }
      };
      request(option, function (error, response, body) {
        console.log(body);
        //console.log(JSON.stringify(response));
        var tmp = JSON.parse(body);
        // var list = new Array();
        // var obj = new Object();
        // obj.krw = tmp.krw.available + ""
        // obj.btc = tmp.btc.available + ""
        // obj.zil = tmp.zil.available + ""
        // list.push(obj);
        // console.log(list);
        var result = { krw: tmp.krw.available, zil: tmp.zil.available, trx: tmp.trx.available }
        res.json(result);
      });
    }
  }

})

//계좌 조회
router.post('/lookup', async function (req, res) {
  var email = req.cookies["user"];
  var cashAccessToken;

  if (email == undefined) {
    res.send("1");
  } else {

    await models.user.findOne({
      where: {
        email: email
      }
    })
      .then(result => {
        cashAccessToken = "Bearer " + result.dataValues.cash3leggedToken;
        console.log(cashAccessToken);
      })

    if (cashAccessToken.substring(7, 9) != 'ey') {
      res.send("2");
    } else {
      var random = Math.floor(Math.random() * 1000000000);
      console.log(random);

      if (random.toString().length < 9) {
        do {
          random = Math.floor(Math.random() * 1000000000);
        } while (random.toString().length != 9)
        console.log(random);

        // ↓ T랑 U사이에 본인 이용기관 코드(숫자 9자리) 입력하셔야 합니다
        // 사용자한테서 이것도 받아와야 함
        var ranid = 'TU' + random;
      } else {
        var ranid = 'TU' + random;
      }

      console.log("토큰 : " + cashAccessToken);
      var option = {
        method: 'GET',
        url: 'https://testapi.openbanking.or.kr/v2.0/account/balance/fin_num',
        headers: {
          Authorization: cashAccessToken
        },//headers end

        qs: {
          bank_tran_id: ranid,
          // ↓ 각자 계좌 입력하셔야 합니다
          // 사용자한테 이것도 받아와야 함 (향후 계좌 선택하는 화면 추가 구현)
          fintech_use_num: '',
          tran_dtime: ''
        }
      };

      request(option, function (error, response, body) {
        console.log(body);
        var resultObject = JSON.parse(body);
        if (resultObject.rsp_code == 'A0000') {
          res.json(resultObject.balance_amt);
        }
        else {
          res.json(resultObject.rsp_message);
        }
      });
    }
  }
});

// 환전에서 원화 출금
router.post('/ExWithdrawKor', function (req, res) {
  var countnum = Math.floor(Math.random() * 1000000000) + 1;
  var transId = 'T991627800U' + countnum;

  var option = {
    method: 'post',
    url: 'https://testapi.openbanking.or.kr/v2.0/transfer/withdraw/fin_num',
    headers: {
      Authorization: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiIxMTAwNzU5MTMyIiwic2NvcGUiOlsiaW5xdWlyeSIsImxvZ2luIiwidHJhbnNmZXIiXSwiaXNzIjoiaHR0cHM6Ly93d3cub3BlbmJhbmtpbmcub3Iua3IiLCJleHAiOjE1OTgxODAyODYsImp0aSI6Ijk1MTFlZjZkLWIxYmYtNGU1Yy1iOTI2LTExOTM0MmJjNDY3YiJ9.9Bvj78d1uMYDxe7RmCwnf45IZtSKFBpXywZwCqGuy3Y',
      'Content-Type': 'application/json; charset=UTF-8'
    },
    json: {
      bank_tran_id: transId,                      // 은행거래고유번호
      cntr_account_type: 'N',                     // 출금 N:계좌, C:계정
      cntr_account_num: '',             // 출금 약정 계좌/계정 번호
      dps_print_content: '',           // 입금계좌인자내역
      fintech_use_num: '',// 출금계좌핀테크이용번호
      wd_print_content: '오픈뱅킹출금',            // 출금계좌인자내역
      tran_amt: '1000',                           // 거래금액
      tran_dtime: '20200605033510',               // 요청일시
      req_client_name: '홍길동',                   // 요청고객성명
      req_client_bank_code: '097',                // 요청고객계좌개설기관
      req_client_account_num: '1234567890',       // 요청고객계좌번호
      req_client_num: 'HONGGILDONG1234',          // 요청고객회원번호
      transfer_purpose: 'TR',                     // 이체용도(TR:송금, ST:결제, RC:충전)
      // "sub_frnc_name" : "하위가맹점",           // 하위가맹점명
      // "sub_frnc_num" : "123456789012",         // 하위가맹점번호
      // "sub_frnc_business_num" : "1234567890",  // 하위가맹점사업자등록번호
      recv_client_name: '',                  // 최종수취고객성명
      recv_client_bank_code: '097',               // 최종수취고객계좌개설기관
      recv_client_account_num: '1234567890'       // 최종수취고객계좌번호
    }
  }
  request(option, function (error, response, body) {
    console.log(body)
    var resultObject = body
    if (resultObject.rsp_code == 'A0000') {
      res.json(1)
    } else {
      res.json(resultObject.rsp_code)
    }
  })
})

// 환전에서 원화 입금
router.post('/ExDepositKor', function (req, res) {
  var countnum = Math.floor(Math.random() * 1000000000) + 1;
  var transId = 'T991627800U' + countnum;

  var option = {
    method: 'post',
    url: 'https://testapi.openbanking.or.kr/v2.0/transfer/deposit/fin_num',
    headers: {
      Authorization: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJUOTkxNjI3ODAwIiwic2NvcGUiOlsib29iIl0sImlzcyI6Imh0dHBzOi8vd3d3Lm9wZW5iYW5raW5nLm9yLmtyIiwiZXhwIjoxNTk5MDkwMDYzLCJqdGkiOiJhNDEyYzEwNC0zNTgyLTQ0ZjUtYTUyZS1mNzYzMmJhN2JlNWUifQ.djeXTaOKcyCSSOxQmT_hDqlPAwDl7Uu8zowEJDP-ra8',//OOB
      'Content-Type': 'application/json; charset=UTF-8'
    },
    json: {
      cntr_account_type: 'N',                             // 입금 N:계좌, C:계정
      cntr_account_num: '6229019632',                     // 입금 약정 계좌/계정 번호
      wd_pass_phrase: 'NONE',                             // 입금이체용 암호문구
      wd_print_content: '홍길동선물',                      // 출금계좌인자내역
      name_check_option: 'on',                            // 수취인성명 검증 여부(on:검증함, off:검증안함)
      tran_dtime: '20200605084426',                       // 요청일시
      req_cnt: '1',                                       // 입금요청건수
      req_list: [                                         // 입금요청목록
        {
          tran_no: '1',                               // 거래순번
          bank_tran_id: transId,                      // 은행거래고유번호
          fintech_use_num: '',// 핀테크이용번호
          print_content: '',                 // 입금계좌인자내역
          tran_amt: '400',                            // 거래금액
          req_client_name: '',                  // 요청고객성명
          req_client_bank_code: '097',                // 요청고객계좌개설기관
          req_client_account_num: '',       // 요청고객계좌번호
          // req_client_fintech_use_num: '', // 요청고객핀테크이용번호
          req_client_num: '',          // 요청고객회원번호
          transfer_purpose: 'TR'                      // 이체용도(TR:송금, ST:결제, AU:인증)
        }
      ]
    }
  }
  request(option, function (error, response, body) {
    console.log(body)
    var resultObject = body
    if (resultObject.rsp_code == 'A0000') {
      res.json(1)
    } else {
      res.json(resultObject.rsp_code)
    }
  })
})

// 결제에서 원화 출금
router.post('/PayWithdrawKor', async function (req, res) {
  // 3-legged 토큰, 2-legged 토큰 둘 다 있는지 확인해야 됨 (출금, 입금 동시에 하니까)
  // var access_token = req.cookies["coinGetAccessToken"];
  var email = req.cookies["user"];
  var currency = req.body.currency;
  var amount = req.body.amount;
  var address = req.body.address;
  // console.log(currency);
  // console.log(amount.val);
  // console.log(address.val);

  if (email == undefined) {
    res.send("1");
  } else {
    await models.user.findOne({
      where: {
        email: email
      }
    })
      .then(result => {
        cash3leggedToken = "Bearer " + result.dataValues.cash3leggedToken;
        console.log("DB에서 갖고 온 3legged 토큰: " + cash3leggedToken);

        cash2leggedToken = "Bearer " + result.dataValues.cash2leggedToken;
        console.log("DB에서 갖고 온 2legged 토큰: " + cash2leggedToken);
      })

    if (cash3leggedToken.substring(7, 9) != 'ey' && cash2leggedToken.substring(7, 9) != 'ey') {
      // if (access_token == undefined) {
      res.send("2");
    } else {
      // if (1 == 0) {
      if (currency == undefined && amount == undefined && address == undefined) {
        res.send("3")
      } else {

        var enterData = req.decoded;

        var random = Math.floor(Math.random() * 1000000000);
        console.log(random);
        if (random.toString().length < 9) {
          do {
            random = Math.floor(Math.random() * 1000000000);
          } while (random.toString().length != 9)
          console.log(random);

          // ↓ T랑 U사이에 본인 이용기관 코드(숫자 9자리) 입력하셔야 합니다
          // 사용자한테서 이것도 받아와야 함
          var transId = 'TU' + random;
        } else {
          var transId = 'TU' + random;
        }

        var option = {
          method: 'post',
          url: 'https://testapi.openbanking.or.kr/v2.0/transfer/withdraw/fin_num',
          headers: {
            Authorization: cash3leggedToken, //fintech 테이블의 3-leg 토큰
            'Content-Type': 'application/json; charset=UTF-8'
          },
          json: {
            bank_tran_id: transId,
            cntr_account_type: 'N',
            cntr_account_num: '',
            dps_print_content: '페이헬퍼입금',
            fintech_use_num: '',
            wd_print_content: '페이헬퍼출금',
            tran_amt: '10000', // 총액
            tran_dtime: '20200910101921',
            req_client_name: '페헬고객A', // 출금하라고 요청하는 사람(고객A = )
            req_client_bank_code: '097',
            req_client_account_num: '',
            req_client_num: '',
            transfer_purpose: 'TR',
            // "sub_frnc_name" : "하위가맹점",
            // "sub_frnc_num" : "123456789012",
            // "sub_frnc_business_num" : "1234567890",
            recv_client_name: '페헬고객B', // 최종 입금받는 사람(고객B = )
            recv_client_bank_code: '097',
            recv_client_account_num: '123123123123'
          }
        };
        request(option, function (error, response, body) {
          console.log(body);
          var resultObject = body;
          if (resultObject.rsp_code == 'A0000') {
            res.render('user/payment', { email: req.cookies['user'], flag10: "출금완료" });
          } else {
            res.render('user/payment', { email: req.cookies['user'], flag10: "출금실패" });
          }
        });
      }
    }
  }
});

// 결제에서 원화 입금
router.post('/PayDepositKor', async function (req, res) {
  var email = req.cookies["user"];
  var cash2leggedToken;

  await models.user.findOne({
    where: {
      email: email
    }
  })
    .then(result => {
      cash2leggedToken = "Bearer " + result.dataValues.cash2leggedToken;
      console.log("DB에서 갖고 온 2legged 토큰: " + cash2leggedToken);
    })

  var random = Math.floor(Math.random() * 1000000000);
  console.log(random);
  if (random.toString().length < 9) {
    do {
      random = Math.floor(Math.random() * 1000000000);
    } while (random.toString().length != 9)
    console.log(random);

    // ↓ T랑 U사이에 본인 이용기관 코드(숫자 9자리) 입력하셔야 합니다
    // 사용자한테서 이것도 받아와야 함
    var ranId = 'TU' + random;
  } else {
    var ranId = 'TU' + random;
  }

  var options = {
    method: 'POST',
    url: 'https://testapi.openbanking.or.kr/v2.0/transfer/deposit/fin_num',
    headers: {
      Authorization: cash2leggedToken, //fintech 테이블의 2-leg 토큰
      'Content-Type': 'application/json; charset=UTF-8'
    },
    json: {
      cntr_account_type: 'N',
      cntr_account_num: '',
      wd_pass_phrase: 'NONE',
      wd_print_content: '페이헬퍼출금',
      name_check_option: 'on',
      tran_dtime: '20200110102959',
      req_cnt: '1',
      req_list: [ // 가맹점 1곳이라고 가정. 여러 곳일 때도 가능하게 확장 예정
        {
          tran_no: '1',
          bank_tran_id: ranId,
          fintech_use_num: '',
          print_content: '페이헬퍼입금',
          tran_amt: '10000',
          req_client_name: '페이헬퍼A',
          req_client_bank_code: '097',
          req_client_account_num: '',
          // req_client_fintech_use_num: '',
          req_client_num: 'HONGGILDONG1234',
          transfer_purpose: 'TR'
        }
      ]
    }
  };
  request(options, function (error, response, body) {
    console.log(body);
    var resultObject = body;
    if (resultObject.rsp_code == 'A0000') {
      res.json(1);
    } else {
      res.json(resultObject.rsp_code);
    }
  });
});


// payCoin POST
router.post('/payCoin', function (req, res) {
  var access_token = req.cookies["coinGetAccessToken"];
  var email = req.cookies["user"];
  var cryptocurrency = req.body.cryptocurrency;
  var amount = req.body.amount;
  var address = req.body.address;
  console.log(cryptocurrency);
  console.log(amount);
  console.log(address);

  if (email == undefined) {
    res.send("1");
  } else {
    if (access_token == undefined) {
      res.send("2");
    } else {
      if (cryptocurrency == undefined && amount == undefined && address == undefined) {
        res.send("3")
      } else {
        var option = {
          url: 'https://api.korbit.co.kr/v1/user/coins/out',
          method: 'POST',
          headers: {
            Authorization: 'Bearer ' + access_token
          },
          qs: {
            currency: cryptocurrency,
            amount: amount,
            address: address,
            nonce: Math.floor(Date.now())
          }
        };
        request(option, function (error, response, body) {
          console.log(JSON.stringify(response));
          console.log(body);
          var tmp = JSON.parse(body);
          if (!body) {
            res.render('user/payment', { email: req.cookies['user'], flag1: tmp.status });
          } else {
            models.pay.create({
              email: email,
              cryptocurrency: cryptocurrency,
              transferId: tmp.transferId
            })
            res.render('user/payment', { email: req.cookies['user'], flag1: tmp.status, flag5: cryptocurrency + " " + tmp.transferId });
          }
        });
      }
    }
  }

})

// payCoin2 POST
router.post('/payCoin2', async function (req, res) {
  var access_token = req.cookies["coinGetAccessToken"];
  var email = req.cookies["user"];
  var cryptocurrency = req.body.cryptocurrency;
  var amount = req.body.amount;
  var coin = req.body.coin;
  var address = req.body.address;
  console.log(cryptocurrency);
  console.log(amount);
  console.log(coin);
  console.log(address);
  var masterAddress;
  var cash2leggedToken;
  if (cryptocurrency == "zil") {
    masterAddress = ''
  } else if (cryptocurrency == "trx") {
    masterAddress = ''
  }

  if (email == undefined) {
    res.send("1");
  } else {
    await models.user.findOne({
      where: {
        email: email
      }
    })
      .then(result => {
        cash2leggedToken = "Bearer " + result.dataValues.cash2leggedToken;
        console.log("DB에서 갖고 온 2legged 토큰: " + cash2leggedToken);
      })
    if (access_token == undefined || cash2leggedToken.substring(7, 9) != 'ey') {
      if (access_token == undefined) {
        res.send("2");
      } else if (cash2leggedToken.substring(7, 9) != 'ey') {
        res.send("4");
      }
    } else {
      if (cryptocurrency == undefined && amount == undefined && coin == undefined && address == undefined) {
        res.send("3")
      } else {
        var option1 = {
          url: 'https://api.korbit.co.kr/v1/user/coins/out',
          method: 'POST',
          headers: {
            Authorization: 'Bearer ' + access_token
          },
          qs: {
            currency: cryptocurrency,
            amount: coin,
            address: masterAddress,
            nonce: Math.floor(Date.now())
          }
        };

        var random = Math.floor(Math.random() * 1000000000);
        console.log(random);
        if (random.toString().length < 9) {
          do {
            random = Math.floor(Math.random() * 1000000000);
          } while (random.toString().length != 9)
          console.log(random);

          // ↓ T랑 U사이에 본인 이용기관 코드(숫자 9자리) 입력하셔야 합니다
          // 사용자한테서 이것도 받아와야 함
          var ranId = 'TU' + random;
        } else {
          var ranId = 'TU' + random;
        }

        var option2 = {
          method: 'POST',
          url: 'https://testapi.openbanking.or.kr/v2.0/transfer/deposit/fin_num',
          headers: {
            Authorization: cash2leggedToken, //fintech 테이블의 2-leg 토큰
            'Content-Type': 'application/json; charset=UTF-8'
          },
          json: {
            cntr_account_type: 'N',
            cntr_account_num: '',
            wd_pass_phrase: 'NONE',
            wd_print_content: '페이헬퍼출금',
            name_check_option: 'on',
            tran_dtime: '20200110102959',
            req_cnt: '1',
            req_list: [ // 가맹점 1곳이라고 가정. 여러 곳일 때도 가능하게 확장 예정
              {
                tran_no: '1',
                bank_tran_id: ranId,
                fintech_use_num: '',
                print_content: '페이헬퍼입금',
                tran_amt: '10000',
                req_client_name: '페헬고객A',
                req_client_bank_code: '097',
                req_client_account_num: '',
                // req_client_fintech_use_num: '',
                req_client_num: 'HONGGILDONG1234',
                transfer_purpose: 'TR'
              }
            ]
          }
        };

        request(option1, function (error, response, body) {
          console.log(JSON.stringify(response));
          console.log(body);
          var tmp = JSON.parse(body);
          if (!body) {
            res.render('user/payment', { email: req.cookies['user'], flag13: tmp.status }); //가상화폐 출금 실패
          } else {
            models.pay.create({
              email: email,
              cryptocurrency: cryptocurrency,
              transferId: tmp.transferId
            })
            request(option2, function (error, response, body) {
              console.log(body);
              var resultObject = body;
              if (resultObject.rsp_code == 'A0000') {
                res.render('user/payment', { email: req.cookies['user'], flag13: tmp.status, flag14: "입금완료" }); // 가상화폐 출금 성공 + 현금 입금 성공
              } else {
                res.render('user/payment', { email: req.cookies['user'], flag13: tmp.status, flag14: "입금실패" }); // 가상화폐 출금 성공 + 현금 입금 실패
              }
            });
          }
        });
      }
    }
  }

})

// payKor2 POST
router.post('/payKor2', function (req, res) {
  var options = {
    url: 'https://api.korbit.co.kr/v1/oauth2/access_token',
    method: 'POST',
    qs: {
      client_id: '',
      client_secret: '',
      grant_type: 'client_credentials'
    }
  };
  request(options, async function (error, response, body) {
    console.log(body);
    var tmps = JSON.parse(body);
    console.log(tmps.access_token);
    //var access_token = req.cookies["coinGetAccessToken"];

    var email = req.cookies["user"];
    var cryptocurrency = req.body.cryptocurrency;
    var amount = req.body.amount;
    var won2 = req.body.won2;
    var address = req.body.address;
    var cash3leggedToken;
    console.log(cryptocurrency);
    console.log(amount);
    console.log(won2);
    console.log(address);
    if (email == undefined) {
      res.send("1");
    } else {
      await models.user.findOne({
        where: {
          email: email
        }
      })
        .then(result => {
          cash3leggedToken = "Bearer " + result.dataValues.cash3leggedToken;
          console.log("DB에서 갖고 온 3legged 토큰: " + cash3leggedToken);
        })
      if (cash3leggedToken.substring(7, 9) != 'ey') {
        res.send("2");
      } else {
        if (cryptocurrency == undefined && amount == undefined && won2 == undefined && address == undefined) {
          res.send("3")
        } else {

          var enterData = req.decoded;

          var random = Math.floor(Math.random() * 1000000000);
          console.log(random);
          if (random.toString().length < 9) {
            do {
              random = Math.floor(Math.random() * 1000000000);
            } while (random.toString().length != 9)
            console.log(random);

            // ↓ T랑 U사이에 본인 이용기관 코드(숫자 9자리) 입력하셔야 합니다
            // 사용자한테서 이것도 받아와야 함
            var transId = 'TU' + random;
          } else {
            var transId = 'TU' + random;
          }

          var option1 = {
            method: 'post',
            url: 'https://testapi.openbanking.or.kr/v2.0/transfer/withdraw/fin_num',
            headers: {
              Authorization: cash3leggedToken, //fintech 테이블의 3-leg 토큰
              'Content-Type': 'application/json; charset=UTF-8'
            },
            json: {
              bank_tran_id: transId,
              cntr_account_type: 'N',
              cntr_account_num: '',
              dps_print_content: '페이헬퍼입금',
              fintech_use_num: '',
              wd_print_content: '페이헬퍼출금',
              tran_amt: '10000', // 총액
              tran_dtime: '20200910101921',
              req_client_name: '페헬고객A', // 출금하라고 요청하는 사람(고객A = )
              req_client_bank_code: '097',
              req_client_account_num: '',
              req_client_num: 'HONGGILDONG1234',
              transfer_purpose: 'TR',
              // "sub_frnc_name" : "하위가맹점",
              // "sub_frnc_num" : "",
              // "sub_frnc_business_num" : "",
              recv_client_name: '페헬고객B', // 최종 입금받는 사람(고객B = )
              recv_client_bank_code: '097',
              recv_client_account_num: ''
            }
          };

          var option2 = {
            url: 'https://api.korbit.co.kr/v1/user/coins/out',
            method: 'POST',
            headers: {
              Authorization: 'Bearer ' + tmps.access_token
            },
            qs: {
              currency: cryptocurrency,
              amount: amount,
              address: address,
              nonce: Math.floor(Date.now())
            }
          };

          request(option1, function (error, response, body) {
            console.log(body);
            var resultObject = body;
            if (resultObject.rsp_code == 'A0000') {
              request(option2, function (error, response, body) {
                console.log(JSON.stringify(response));
                console.log(body);
                var tmp = JSON.parse(body);
                if (!body) {
                  res.render('user/payment', { email: req.cookies['user'], flag11: "출금완료", flag12: tmp.status });
                } else {
                  models.pay.create({
                    email: 'tkllll@naver.com',
                    cryptocurrency: cryptocurrency,
                    transferId: tmp.transferId
                  })
                  res.render('user/payment', { email: req.cookies['user'], flag11: "출금완료", flag12: tmp.status });
                }
              });
            } else {
              res.render('user/payment', { email: req.cookies['user'], flag11: "출금실패", flag12: "undefined" });
            }
          });
        }
      }
    }
  });

})



// cancelCoin POST
router.post('/cancelCoin', function (req, res) {
  var access_token = req.cookies["coinGetAccessToken"];
  var email = req.cookies["user"];
  var string = req.body.id.split(" ");
  var cryptocurrency = string[0];
  var id = string[1];
  console.log(cryptocurrency);
  console.log(id);

  if (email == undefined) {
    res.send("1");
  } else {
    if (access_token == undefined) {
      res.send("2");
    } else {
      if (cryptocurrency == undefined && id == undefined) {
        res.send("3");
      } else {
        var option = {
          url: 'https://api.korbit.co.kr/v1/user/coins/out/cancel',
          method: 'POST',
          headers: {
            Authorization: 'Bearer ' + access_token
          },
          qs: {
            currency: cryptocurrency,
            id: id,
            nonce: Math.floor(Date.now())
          }
        };
        request(option, function (error, response, body) {
          console.log(JSON.stringify(response));
          console.log(body);
          var tmp = JSON.parse(body);
          // var arr = Array();
          // for (var i = 0; i < tmp.length; i++) {
          //   //console.log(tmp[i].id);
          //   arr.push(tmp[i].status);
          // }
          //console.log(arr);
          if (tmp.length == 0) {
            res.render('user/payment', { email: req.cookies['user'] });
          } else {
            if (tmp.status == "success" || tmp.status == "already_filled" || tmp.status == "not_found" || tmp.status == "invalid_status") {
              models.pay.destroy({
                where: {
                  transferId: id
                }
              })
            }
            res.render('user/payment', { email: req.cookies['user'], flag3: tmp.status });
          }
        });
      }

    }
  }

})

// cancelCoin2 POST
router.post('/cancelCoin2', function (req, res) {
  var access_token = req.cookies["coinGetAccessToken"];
  var email = req.cookies["user"];
  var cryptocurrency = req.body.cryptocurrency;
  var id;
  console.log(cryptocurrency);
  console.log(id);

  if (email == undefined) {
    res.send("1");
  } else {
    if (access_token == undefined) {
      res.send("2");
    } else {
      if (cryptocurrency == undefined) {
        res.send("3");
      } else {
        models.pay.findAll({
          where: {
            email: email,
            cryptocurrency: cryptocurrency
          }
        })
          .then(result => {
            console.log(result.length);
            var arr = Array();
            for (var i = 0; i < result.length; i++) {
              arr.push(result[i].dataValues.cryptocurrency + " " + result[i].dataValues.transferId);
            }
            if (result.length == 0) {
              res.render('user/payment', { email: req.cookies['user'], flag7: "미결제내역이 없습니다." });
            } else {
              res.render('user/payment', { email: req.cookies['user'], flag6: arr });
            }
          })
      }

    }
  }

})

// sellCoinCheck POST
router.post('/sellCoinCheck', function (req, res) {
  var access_token = req.cookies["coinGetAccessToken"];
  var email = req.cookies["user"];
  var currency_pair = req.body.currency_pair;
  var type = 'limit';
  var price = '';
  var coin_amount = req.body.coin_amount;

  if (email == undefined) {
    res.send("1");
  } else {
    if (access_token == undefined) {
      res.send("2");
    } else {
      if (currency_pair == undefined && coin_amount == undefined) {
        res.send("3");
      }
    }
  }
})

// sellCoin POST
router.post('/sellCoin', function (req, res) {
  var access_token = req.cookies["coinGetAccessToken"];
  // var email = req.cookies["user"];
  var currency_pair = req.body.currency_pair;
  var type = 'limit';
  var price = '';
  var coin_amount = req.body.coin_amount;

  if (currency_pair == 'zil_krw') {
    var options = {
      url: 'https://api.korbit.co.kr/v1/ticker',
      method: 'GET',
      qs: {
        currency_pair: currency_pair
      }
    }
    function a() {
      return new Promise(resolve => {
        request(options, function (error, response, body) {
          var tmp = JSON.parse(body);
          //console.log(JSON.stringify(response));
          resolve(tmp.last);
        })
      })
    }
  } else {
    var options = {
      url: 'https://api.korbit.co.kr/v1/ticker',
      method: 'GET',
      qs: {
        currency_pair: currency_pair
      }
    }
    function a() {
      return new Promise(resolve => {
        request(options, function (error, response, body) {
          var tmp = JSON.parse(body);
          //console.log(JSON.stringify(response));
          resolve(tmp.last);
        })
      })
    }
  }
  a().then(function (result) {
    price = result;
    console.log(price);
    var option = {
      url: 'https://api.korbit.co.kr/v1/user/orders/sell',
      method: 'POST',
      headers: {
        Authorization: 'Bearer ' + access_token
      },
      qs: {
        currency_pair: currency_pair,
        type: type,
        price: price,
        coin_amount, coin_amount,
        nonce: Math.floor(Date.now())
      }
    };

    // 여기에 오픈뱅킹 입금 API 써야 됨
    var random = Math.floor(Math.random() * 1000000000);
    console.log(random);
    if (random.toString().length < 9) {
      do {
        random = Math.floor(Math.random() * 1000000000);
      } while (random.toString().length != 9)
      console.log(random);

      // ↓ T랑 U사이에 본인 이용기관 코드(숫자 9자리) 입력하셔야 합니다
      // 사용자한테서 이것도 받아와야 함
      var ranId = 'TU' + random;
    } else {
      var ranId = 'TU' + random;
    }

    var option2 = {
      method: 'POST',
      url: 'https://testapi.openbanking.or.kr/v2.0/transfer/deposit/fin_num',
      headers: {
        Authorization: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJUOTkxNjA1NTMwIiwic2NvcGUiOlsib29iIl0sImlzcyI6Imh0dHBzOi8vd3d3Lm9wZW5iYW5raW5nLm9yLmtyIiwiZXhwIjoxNjEwODEzODMyLCJqdGkiOiIxZmRlZGMyYi05NWUxLTQyM2EtYTBmYS0zOTU0NjZhMmNiMDIifQ.sWF6Za4V9q-6P3njCGCT-4WJD3Za7tD3-_OTW3aP14c',
        'Content-Type': 'application/json; charset=UTF-8'
      },
      json: {
        cntr_account_type: 'N',
        cntr_account_num: '',
        wd_pass_phrase: 'NONE',
        wd_print_content: '',
        name_check_option: 'on',
        tran_dtime: '20200110102959',
        req_cnt: '1',
        req_list: [ // 가맹점 1곳이라고 가정. 여러 곳일 때도 가능하게 확장 예정
          {
            tran_no: '1',
            bank_tran_id: ranId,
            fintech_use_num: '',
            print_content: '',
            tran_amt: '1000',
            req_client_name: '홍길동',
            req_client_bank_code: '097',
            req_client_account_num: '',
            req_client_num: 'HONGGILDONG1234',
            transfer_purpose: 'TR'
          }
        ]
      }
    };
    request(option2, function (error, response, body) {
      console.log(body);
      var resultObject = body;
      if (resultObject.rsp_code == 'A0000') {
        // res.json(1);
        console.log("입금 완료!");
      } else {
        // res.json(resultObject.rsp_code);
        console.log("입금 실패!" + resultObject.rsp_code);
      }
    });

    request(option, function (error, response, body) {
      console.log(JSON.stringify(response));
      console.log(body);
      var tmp = JSON.parse(body);
      if (!body) {
        res.render('user/exchange', { email: req.cookies['user'] });
      } else {
        res.render('user/exchange', { email: req.cookies['user'], flag1: tmp.status });
      }
    });
  })
})

// buyCoinCheck POST
router.post('/buyCoinCheck', function (req, res) {
  var access_token = req.cookies["coinGetAccessToken"];
  var email = req.cookies["user"];
  var currency_pair = req.body.currency_pair;
  var type = 'limit';
  var price = '';
  var coin_amount = req.body.coin_amount;

  if (email == undefined) {
    res.send("1");
  } else {
    if (access_token == undefined) {
      res.send("2");
    } else {
      if (currency_pair == undefined && coin_amount == undefined) {
        res.send("3");
      }
    }
  }
})

// buyCoin POST
router.post('/buyCoin', function (req, res) {
  var access_token = req.cookies["coinGetAccessToken"];
  // var email = req.cookies["user"];
  var currency_pair = req.body.currency_pair;
  var type = 'limit';
  var price = '';
  var coin_amount = req.body.coin_amount;

  if (currency_pair == 'zil_krw') {
    var options = {
      url: 'https://api.korbit.co.kr/v1/ticker',
      method: 'GET',
      qs: {
        currency_pair: currency_pair
      }
    }
    function a() {
      return new Promise(resolve => {
        request(options, function (error, response, body) {
          var tmp = JSON.parse(body);
          //console.log(JSON.stringify(response));
          resolve(tmp.last);
        })
      })
    }
  } else {
    var options = {
      url: 'https://api.korbit.co.kr/v1/ticker',
      method: 'GET',
      qs: {
        currency_pair: currency_pair
      }
    }
    function a() {
      return new Promise(resolve => {
        request(options, function (error, response, body) {
          var tmp = JSON.parse(body);
          //console.log(JSON.stringify(response));
          resolve(tmp.last);
        })
      })
    }
  }
  a().then(function (result) {
    price = result;
    console.log(price);
    var option = {
      url: 'https://api.korbit.co.kr/v1/user/orders/buy',
      method: 'POST',
      headers: {
        Authorization: 'Bearer ' + access_token
      },
      qs: {
        currency_pair: currency_pair,
        type: type,
        price: price,
        coin_amount, coin_amount,
        nonce: Math.floor(Date.now())
      }
    };

    // 여기에 오픈뱅킹 출금 API 써야 됨
    var random = Math.floor(Math.random() * 1000000000);
    console.log(random);
    if (random.toString().length < 9) {
      do {
        random = Math.floor(Math.random() * 1000000000);
      } while (random.toString().length != 9)
      console.log(random);

      // ↓ T랑 U사이에 본인 이용기관 코드(숫자 9자리) 입력하셔야 합니다
      // 사용자한테서 이것도 받아와야 함
      var transId = 'TU' + random;
    } else {
      var transId = 'TU' + random;
    }

    var option2 = {
      method: 'post',
      url: 'https://testapi.openbanking.or.kr/v2.0/transfer/withdraw/fin_num',
      headers: {
        Authorization: ''
      },
      json: {
        bank_tran_id: transId,
        cntr_account_type: 'N',
        cntr_account_num: '6633666070',
        dps_print_content: '이용료(홍길동)',
        fintech_use_num: '',
        wd_print_content: '이용료',
        tran_amt: '1000',
        tran_dtime: '',
        req_client_name: '', // 출금하라고 요청하는 사람 / 사실 내가 받음
        req_client_bank_code: '097',
        req_client_account_num: '',
        req_client_num: 'HONGGILDONG1234',
        transfer_purpose: 'TR',
        // "sub_frnc_name" : "하위가맹점",
        // "sub_frnc_num" : "",
        // "sub_frnc_business_num" : "",
        recv_client_name: '김오픈', // 출금하라는 요청을 받았다 / 출금을 하는 주체는 회사
        recv_client_bank_code: '097',
        recv_client_account_num: ''
      }
    };
    request(option2, function (error, response, body) {
      console.log(body);
      var resultObject = body;
      if (resultObject.rsp_code == 'A0000') {
        // res.json(1);
        console.log("출금 완료!");

      } else {
        console.log("출금 실패!" + resultObject.rsp_code);
        // res.json(resultObject.rsp_code);
      }
    });

    request(option, function (error, response, body) {
      console.log(JSON.stringify(response));
      console.log(body);
      var tmp = JSON.parse(body);
      if (!body) {
        res.render('user/exchange', { email: req.cookies['user'] });
      } else {
        res.render('user/exchange', { email: req.cookies['user'], flag2: tmp.status });
      }
    });
  })
})

// lookupSellOrBuyCoin POST
router.post('/lookupSellOrBuyCoin', function (req, res) {
  var access_token = req.cookies["coinGetAccessToken"];
  var email = req.cookies["user"];
  var currency_pair = req.body.currency_pair;

  if (email == undefined) {
    res.send("1");
  } else {
    if (access_token == undefined) {
      res.send("2");
    } else {
      if (currency_pair == undefined) {
        res.send("3")
      } else {
        var option = {
          url: 'https://api.korbit.co.kr/v1/user/orders/open',
          method: 'GET',
          headers: {
            Authorization: 'Bearer ' + access_token
          },
          qs: {
            currency_pair: currency_pair
          }
        };
        request(option, function (error, response, body) {
          console.log(JSON.stringify(response));
          console.log(body);
          var tmp = JSON.parse(body);
          var arr = Array();
          for (var i = 0; i < tmp.length; i++) {
            console.log(tmp[i].id);
            arr.push(currency_pair + " " + tmp[i].id);
          }
          console.log(arr);
          if (tmp.length == 0) {
            res.render('user/exchange', { email: req.cookies['user'], flag5: "미체결내역이 없습니다." });
          } else {
            res.render('user/exchange', { email: req.cookies['user'], flag3: arr });
          }
        });
      }
    }
  }

})

// cancelSellOrBuyCoin POST
router.post('/cancelSellOrBuyCoin', function (req, res) {
  var access_token = req.cookies["coinGetAccessToken"];
  var email = req.cookies["user"];
  var string = req.body.id.split(" ");
  var currency_pair = string[0];
  var id = string[1];
  console.log(currency_pair);
  console.log(id);

  if (email == undefined) {
    res.send("1");
  } else {
    if (access_token == undefined) {
      res.send("2");
    } else {
      if (currency_pair == undefined && id == undefined) {
        res.send("3")
      } else {
        var option = {
          url: 'https://api.korbit.co.kr/v1/user/orders/cancel',
          method: 'POST',
          headers: {
            Authorization: 'Bearer ' + access_token
          },
          qs: {
            currency_pair: currency_pair,
            id: id
          }
        };
        request(option, function (error, response, body) {
          console.log(JSON.stringify(response));
          console.log(body);
          var tmp = JSON.parse(body);
          var arr = Array();
          for (var i = 0; i < tmp.length; i++) {
            //console.log(tmp[i].id);
            arr.push(tmp[i].status);
          }
          //console.log(arr);
          if (tmp.length == 0) {
            res.render('user/exchange', { email: req.cookies['user'] });
          } else {
            res.render('user/exchange', { email: req.cookies['user'], flag4: arr });
          }
        });
      }
    }
  }

})

module.exports = router;