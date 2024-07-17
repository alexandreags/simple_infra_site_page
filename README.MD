# 🚀 Máquina Info - O Monitor Mais Daora da Sua Infra!

E aí, galera! Bem-vindos ao **Máquina Info**, o app mais descolado pra ficar de olho na sua infra. Se liga só nas paradas que esse sistema faz:

## 🎯 Funcionalidades Maneiras

- 👀 Mostra as infos básicas da máquina (hostname, IP, espaço em disco)
- 📊 Monitora o uso de CPU e memória em tempo real
- 🖱️ Conta os cliques e mostra num gráfico animal
- 💾 Avisa quando o disco tá ficando lotado
- 🔐 Sistema de login pra manter os curiosos longe

## 🛠️ Tecnologias Usadas

- Node.js: O coração do backend
- Express: Pra criar as rotas rapidinho
- MySQL: Guardando os dados como um cofre
- Passport: Cuidando da autenticação dos users
- Chart.js: Fazendo aqueles gráficos bonitos
- Tailwind CSS: Deixando o frontend todo elegante

## 🏃‍♂️ Como Rodar Essa Belezinha

1. Primeiro, clona o repo:
   ```
   git clone https://github.com/seu-usuario/maquina-info.git
   ```

2. Entra na pasta do projeto:
   ```
   cd maquina-info
   ```

3. Instala as dependências:
   ```
   npm install
   ```

4. Configura o arquivo `.env` com as infos do seu banco de dados e outras configs:
   ```
   DB_HOST=localhost
   DB_USER=seu_usuario
   DB_PASSWORD=sua_senha
   DB_NAME=nome_do_banco
   SESSION_SECRET=algum_segredo_bem_dificil
   PORT=3000
   ```

5. Roda o script do banco :
   ```
   create_table.sql
   ```

7. Bota pra rodar:
   ```
   npm start
   ```

8. Abre o navegador e acessa `http://localhost:3000`. Tá no ar, parça!



## 📜 Licença

Este projeto está sob a licença MIT. Vê o arquivo `LICENSE` pra mais detalhes.
