const express = require('express')
const fs = require("fs");
var cors = require('cors')
const jose = require("node-jose");
const app = express()
const port = 3000

app.use(cors())
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

function ms(duration) {
    const regex = /(\d+)(ms|[smhdwMy])/;
    const matches = duration.match(regex);
  
    if (!matches) {
      throw new Error(`Invalid duration: ${duration}`);
    }
  
    const value = parseInt(matches[1], 10);
    const unit = matches[2];
  
    switch (unit) {
      case "ms":
        return value;
      case "s":
        return value * 1000;
      case "m":
        return value * 60 * 1000;
      case "h":
        return value * 60 * 60 * 1000;
      case "d":
        return value * 24 * 60 * 60 * 1000;
      case "w":
        return value * 7 * 24 * 60 * 60 * 1000;
      case "M":
        return value * 30 * 24 * 60 * 60 * 1000;
      case "y":
        return value * 365 * 24 * 60 * 60 * 1000;
      default:
        throw new Error(`Invalid duration unit: ${unit}`);
    }
  }
  
app.get('/oauth2/jwks', async(req, res) => {
    const ks = fs.readFileSync("keys.json");
    const keyStore = await jose.JWK.asKeyStore(ks.toString());
    console.log('/oauth2/jwks');
    res.send(keyStore.toJSON());
})

app.get('/oauth2/token', async(req, res) => {
    const {type} = req.query;

    const JWKeys = fs.readFileSync("keys.json");
    const keyStore = await jose.JWK.asKeyStore(JWKeys.toString());
    const [key] = keyStore.all({ use: "sig" });
    const opt = { compact: true, jwk: key, fields: { typ: "jwt" } };

    const payload = JSON.stringify({
        exp: Math.floor((Date.now() + ms("10m")) / 1000),
        iat: Math.floor(Date.now() / 1000),
        sub: "test",
        roles: type === 'user' ? ["USER"] : ["ADMIN","USER"]
    });

    const token = await jose.JWS.createSign(opt, key).update(payload).final();
    res.send({ token });
})


app.listen(port, () => {
    console.log(`JWT-JWKS Listening on port ${port}`)
})