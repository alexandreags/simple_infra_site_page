require('dotenv').config();
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');

async function createUser(username, password) {
    const connection = await mysql.createConnection({
        host: process.env.DB_HOST,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME
    });

    const hashedPassword = await bcrypt.hash(password, 10);

    try {
        await connection.execute(
            'INSERT INTO users (username, password) VALUES (?, ?)',
            [username, hashedPassword]
        );
        console.log('Usuário criado com sucesso!');
    } catch (error) {
        console.error('Erro ao criar usuário:', error);
    } finally {
        await connection.end();
    }
}

// Exemplo de uso:
createUser('admin', 'password');