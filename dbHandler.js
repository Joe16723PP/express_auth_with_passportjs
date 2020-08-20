import fs from 'fs';
import path from 'path';
import bcrypt from 'bcrypt';

const __dirname = path.resolve();
const dbPath = __dirname + '/database/db.json';
const saltRound = 5;

export const readUsers = () => {
    const res = fs.readFileSync(dbPath, 'utf8');
    return JSON.parse(res);
}

export const getUserByName = (name) => {
    const users = readUsers();
    return users['users'].filter(value => {
        return value.username === name;
    });

}

export const writeUsers = (username, password) => {
    const response = readUsers();
    const user = {
        username,
        password
    }
    // hash password 
    const salt = bcrypt.genSaltSync(saltRound);
    const hashPwd = bcrypt.hashSync(user.password, salt);
    // change plaintext to hash value
    user.password = hashPwd;
    response['users'].push(user);
    try {
        fs.writeFileSync(dbPath, JSON.stringify(response));
        return true;
    } catch(err) {
        return false;
    }
}

export const authUser = (username, password) => {
    const response = readUsers();
    let isAuth = false;
    const authUser = {
        username,
        password
    }
    for (const user of response['users']) {
        const isValid = bcrypt.compareSync(authUser.password, user.password); 
        const condition = user.username === authUser.username && isValid;
        if (condition) {
            isAuth = true;
            break;
        }
    }

    return isAuth;
}

export const checkUsername = (username) => {
    const response = readUsers();
    let isAuth = false;
    for (const user of response['users']) {
        const condition = user.username === username;
        if (condition) {
            isAuth = true;
            break;
        }
    }
    return isAuth;
}