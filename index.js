import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import passport from 'passport';
import passportJwt from 'passport-jwt';
import { readUsers, writeUsers, authUser, checkUsername, getUserByName } from './dbHandler.js';

const app = express();
const port = 3000;
const privateKey = '1q2w3r44t';
const jwtStrategy = passportJwt.Strategy;
const extractJwt = passportJwt.ExtractJwt;
const jwtOptions = {
    jwtFromRequest: extractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: privateKey
};

const generateToken = (username) => {
    const payload = {
        username: username
    };
    const options = {
        algorithm: 'HS256',
        expiresIn: '1h'
    }
    return jwt.sign(payload, privateKey, options);

}

const jwtAuthentication = new jwtStrategy(jwtOptions, (payload, next) => {
    const isValid = checkUsername(payload.username);
    next(null, isValid);
});

passport.use(jwtAuthentication);

const authMiddlewhere = passport.authenticate('jwt', { session: false });


app.use(bodyParser.json());
app.use(cors());

app.get('/', (req, res) => {
    res.json({ msg: "my authentication server" });
});

app.get('/testAuth', authMiddlewhere, (req, res) => {
    res.json({ msg: "auth" });
})

app.get('/users', (req, res) => {
    const users = readUsers();
    res.json(users);
})

app.get('/users/:name', (req, res) => {
    const user = getUserByName(req.params.name);
    if (user.length === 0) {
        res.status('404').json({msg: 'user not found'});
    }
    res.json(user[0]);
})

app.post('/signin', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    const isAuth = authUser(username, password);

    if (isAuth) {
        const token = generateToken(username);
        res.json({ token: token });
    } else {
        res.status('401').json({ msg: "user unauthorized" });
    }
})

app.post('/signup', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    const isSuccess = writeUsers(username, password);

    if (isSuccess) {
        const token = generateToken(username);
        res.json({ token: token });
    } else {
        res.status('402').json({ msg: "user is duplicated" });
    }
})

app.listen(port, () => {
    console.log(`listen on http://localhost:${port}`);
});