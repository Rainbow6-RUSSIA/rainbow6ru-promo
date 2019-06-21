require('dotenv').config();

const express = require('express');
const path = require('path');
const http = require('http');
const fetch = require('node-fetch');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const socketIO = require('socket.io');
const EventEmitter = require('events');
const crypto = require('crypto');

const ee = new EventEmitter();
const CODE = process.env.CODE;
const PORT = process.env.PORT || 3000;
// const SALT = makeSalt();
const STAFF = process
    .env
    .TARGET_STAFF
    .split(',');
// let i = 1;
// let promo = crypto
//     .createHash('md5')
//     .update(SALT + 1)
//     .digest('hex')
//     .slice(0, 8);

const app = express();
const server = http.createServer(app);
const io = socketIO(server);

app.use(bodyParser.urlencoded({extended: false}));
app.use(cookieParser());

// function makeSalt() {
//     var text = "";
//     var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

//     for (var i = 0; i < 16; i++)
//         text += possible.charAt(Math.floor(Math.random() * possible.length));

//     return text;
// }

// function updatePromo() {
//     i++;
//     promo = crypto
//         .createHash('md5')
//         .update(SALT + i)
//         .digest('hex')
//         .slice(0, 8);
//     ee.emit('updatePromo');
// }

const algorithm = 'aes-128-ctr'

function encrypt(text){
    let cipher = crypto.createCipher(algorithm, CODE)
    let crypted = cipher.update(text,'utf8','hex')
    crypted += cipher.final('hex');
    return crypted;
  }

function decrypt(text){
    let decipher = crypto.createDecipher(algorithm, CODE)
    let dec = decipher.update(text,'hex','utf8')
    dec += decipher.final('utf8');
    return dec;
}

async function getUser(token) {
    if (!token)
        throw new Error('InvalidToken')

    const answ = await fetch(`https://discordapp.com/api/users/@me`, {
        method: 'GET',
        headers: {
            Authorization: `Bearer ${token}`
        }
    });
    const user = await answ.json();

    if (user.code === 0)
        throw new Error('InvalidToken')

    return user;
}

async function getGuilds(token) {
    if (!token)
        throw new Error('InvalidToken')

    const answ = await fetch(`https://discordapp.com/api/users/@me/guilds`, {
        method: 'GET',
        headers: {
            Authorization: `Bearer ${token}`
        }
    });
    const guilds = await answ.json();

    if (guilds.code === 0)
        throw new Error('InvalidToken')

    return guilds;
}

app.get('/', async(req, res) => {
    res.redirect(`https://discordapp.com/api/oauth2/authorize?client_id=${process.env.DISCORD_ID}&redirect_uri=${encodeURIComponent(process.env.REDIRECT_URI)}&response_type=code&scope=identify%20guilds`)
})

app.get('/auth', async(req, res) => {
    try {
        if (!req.query.code)
        throw new Error('Unathorized')
        const url = `https://discordapp.com/api/v6/oauth2/token`
        const answ = await fetch(url, {method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded'}, body: new URLSearchParams({
            client_id: process.env.DISCORD_ID,
            client_secret: process.env.DISCORD_SECRET,
            grant_type: 'authorization_code',
            code: req.query.code,
            redirect_uri: process.env.REDIRECT_URI,
            scope: 'guilds%20identify',
        })});
        const json = await answ.json();
        res.cookie('token', json.access_token);
        const user = await getUser(json.access_token);
        if (!STAFF.includes(user.id)) {
            res.redirect('/a')
            return
        }
        res.sendFile(path.join(__dirname + '/pages/promo-return.html'))
    } catch (err) {
        console.log(err.stack);
        res.redirect('/');
    }
})

// app.get('/proceed', async(req, res) => {
//     try {



//

//
//     } catch (err) {
//         console.log(err.stack);
//         res.redirect('/');
//     }
// })

app.get('/c/:code', async(req, res) => {
    try {
        console.log('Calling code')
        const user = await getUser(req.cookies.token);
        console.log('Got user')
        if (!STAFF.includes(user.id)) {
            console.log('Redirect to a')
            res.redirect('/a/')
            return
        }
        const id = decrypt(req.params.code);
		console.log("​id", id)
        if (id.length < 16) {
            res.sendFile(path.join(__dirname + '/pages/promo-err.html'))
            return
        }

        const url = `https://discordapp.com/api/v6/guilds/${process.env.TARGET_ID}/members/${id}`;

        console.log(url)

        const m = await fetch(url, {
            method: 'GET',
            headers: {
                Authorization: `Bot ${process.env.DISCORD_TOKEN}`
            }
        })
        const member = await m.json();

        if (member.roles.includes(process.env.TARGET_ROLE)) {
            res.sendFile(path.join(__dirname + '/pages/promo-already.html'));
        } else {
            await fetch(url + `/roles/${process.env.TARGET_ROLE}`, {
                headers: {
                    Authorization: `Bot ${process.env.DISCORD_TOKEN}`
                },
                method: 'PUT'
            })
            res.sendFile(path.join(__dirname + '/pages/promo-succ.html'))
        }
        // res.cookie('promo', )
        // res.redirect('/proceed')
    } catch (err) {
        console.log(err.stack);
        res.redirect('/');
    }
})

app.get('/a/', async(req, res) => {
    try {
        // const user = await getUser(req.cookies.token);
        const guilds = await getGuilds(req.cookies.token);
        if (!guilds.some(g => g.id === process.env.TARGET_ID)) {
            res.sendFile(path.join(__dirname + '/pages/invite.html'))
            return
        }
        res.sendFile(path.join(__dirname + '/pages/qr.html'));
    } catch (err) {
        console.log(err.stack);
        res.redirect('/')
    }
})

io
    .sockets
    .on('connection', async(socket) => {
        try {
            console.log('Connection attempt');
            const user = await getUser(socket.handshake.query.token);
            socket.emit('message', {promo: encrypt(user.id)});
        } catch (err) {
            socket.disconnect();
            console.log(err.stack);
        }
    })

app.set('port', PORT);
server.listen(PORT, '0.0.0.0');
server.on('listening', () => console.log('Listening on ' + PORT))