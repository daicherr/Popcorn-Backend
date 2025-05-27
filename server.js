// server.js (ou index.js) - Arquivo principal do seu backend

// 1. Importar dependências
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs'); // Para criptografar senhas
const jwt = require('jsonwebtoken'); // Para gerar tokens de autenticação
const cors = require('cors'); // Para permitir requisições de diferentes origens (seu app React Native)
const axios = require('axios');

// Para carregar variáveis de ambiente (ex: string de conexão do MongoDB Atlas)
require('dotenv').config();

// 2. Inicializar a aplicação Express
const app = express();
const PORT = process.env.PORT || 5001; // Porta do servidor (pode ser 3000, 5000, etc.)

// 3. Middlewares
app.use(cors()); // Habilita CORS para todas as rotas
app.use(express.json()); // Permite que o Express entenda requisições com corpo em JSON

// 4. Conexão com o MongoDB Atlas
const MONGO_URI = process.env.MONGO_ATLAS_URI; // Guarde sua string de conexão numa variável de ambiente .env

if (!MONGO_URI) {
    console.error("ERRO: String de conexão do MongoDB Atlas (MONGO_ATLAS_URI) não definida no arquivo .env");
    process.exit(1); // Encerra a aplicação se a string de conexão não estiver presente
}

mongoose.connect(MONGO_URI, {
    // Opções do Mongoose para evitar warnings de depreciação (podem variar com a versão)
    // useNewUrlParser: true, // Não mais necessário no Mongoose 6+
    // useUnifiedTopology: true, // Não mais necessário no Mongoose 6+
    // useCreateIndex: true, // Não mais suportado no Mongoose 6+
    // useFindAndModify: false, // Não mais suportado no Mongoose 6+
})
.then(() => console.log('Conectado com sucesso ao MongoDB Atlas!'))
.catch(err => {
    console.error('Erro ao conectar ao MongoDB Atlas:', err);
    process.exit(1); // Encerra a aplicação se não conseguir conectar ao DB
});

// 5. Definir o Schema e Model do Usuário com Mongoose
const userSchema = new mongoose.Schema({
    email: {
        type: String,
        required: [true, "O email é obrigatório"],
        unique: true, // Garante que cada email seja único
        trim: true,   // Remove espaços em branco extras
        lowercase: true, // Converte para minúsculas
        match: [/\S+@\S+\.\S+/, 'Por favor, use um email válido.'] // Validação simples de email
    },
    password: {
        type: String,
        required: [true, "A senha é obrigatória"],
        minlength: [6, "A senha deve ter pelo menos 6 caracteres"] // Validação de tamanho mínimo
    },
    // Você pode adicionar outros campos aqui, como nome, data de criação, etc.
    // nome: String,
    createdAt: {
        type: Date,
        default: Date.now
    }
});

// Middleware do Mongoose para criptografar a senha ANTES de salvar o usuário
userSchema.pre('save', async function(next) {
    // Só criptografa a senha se ela foi modificada (ou é nova)
    if (!this.isModified('password')) return next();

    try {
        const salt = await bcrypt.genSalt(10); // Gera um "salt" para a criptografia
        this.password = await bcrypt.hash(this.password, salt); // Criptografa a senha
        next();
    } catch (error) {
        next(error); // Passa o erro para o próximo middleware/tratador de erro
    }
});

// Método para comparar a senha enviada com a senha armazenada (criptografada)
userSchema.methods.comparePassword = async function(candidatePassword) {
    return bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', userSchema); // 'User' será o nome da coleção no MongoDB (geralmente pluralizado para 'users')

// 6. Definir Rotas (Endpoints da API)

// Rota de Cadastro (POST /api/auth/register)
app.post('/api/auth/register', async (req, res) => {
    console.log("Recebida requisição POST em /api/auth/register");
    console.log("Corpo da requisição:", req.body);

    const { email, password } = req.body;

    // Validações básicas
    if (!email || !password) {
        return res.status(400).json({ message: 'Por favor, forneça email e senha.' });
    }
    if (password.length < 6) {
        return res.status(400).json({ message: 'A senha deve ter pelo menos 6 caracteres.' });
    }
    // Validação de email mais robusta pode ser adicionada aqui

    try {
        // Verifica se o usuário já existe
        const existingUser = await User.findOne({ email: email.toLowerCase() });
        if (existingUser) {
            console.log("Tentativa de cadastro com email já existente:", email);
            return res.status(400).json({ message: 'Este email já está em uso.' });
        }

        // Cria um novo usuário
        const newUser = new User({ email, password });
        await newUser.save(); // A senha será criptografada pelo middleware 'pre save'

        console.log("Novo usuário cadastrado com sucesso:", newUser.email, newUser._id);
        // Não envie a senha de volta, mesmo criptografada!
        // Pode enviar um token JWT aqui se quiser logar o usuário automaticamente após o cadastro
        res.status(201).json({ message: 'Usuário cadastrado com sucesso!', userId: newUser._id });

    } catch (error) {
        console.error("Erro no endpoint /api/auth/register:", error);
        if (error.code === 11000) { // Código de erro do MongoDB para chave duplicada (email)
             return res.status(400).json({ message: 'Este email já está em uso (erro de duplicidade).' });
        }
        if (error.name === 'ValidationError') {
            // Extrai mensagens de erro de validação do Mongoose
            const messages = Object.values(error.errors).map(val => val.message);
            return res.status(400).json({ message: messages.join(', ') });
        }
        res.status(500).json({ message: 'Erro interno do servidor ao tentar cadastrar o usuário.' });
    }
});

// Rota de Login (POST /api/auth/login)
app.post('/api/auth/login', async (req, res) => {
    console.log("Recebida requisição POST em /api/auth/login");
    console.log("Corpo da requisição:", req.body);

    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Por favor, forneça email e senha.' });
    }

    try {
        // Encontra o usuário pelo email
        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) {
            console.log("Tentativa de login com email não encontrado:", email);
            return res.status(401).json({ message: 'Email ou senha inválidos.' }); // Mensagem genérica por segurança
        }

        // Compara a senha enviada com a senha armazenada (criptografada)
        const isMatch = await user.comparePassword(password);
        if (!isMatch) {
            console.log("Tentativa de login com senha incorreta para o email:", email);
            return res.status(401).json({ message: 'Email ou senha inválidos.' }); // Mensagem genérica
        }

        // Se as credenciais são válidas, gere um token JWT
        const JWT_SECRET = process.env.JWT_SECRET;
        if (!JWT_SECRET) {
            console.error("ERRO: Segredo JWT (JWT_SECRET) não definido no arquivo .env");
            return res.status(500).json({ message: "Erro de configuração do servidor (segredo JWT)." });
        }

        const tokenPayload = { userId: user._id, email: user.email };
        const token = jwt.sign(
            tokenPayload,
            JWT_SECRET,
            { expiresIn: '1h' } // Token expira em 1 hora (ajuste conforme necessário)
        );

        console.log("Login bem-sucedido para o usuário:", user.email, user._id);
        // Envie o token e algumas informações do usuário (sem a senha!)
        res.status(200).json({
            message: 'Login bem-sucedido!',
            token: token,
            user: {
                id: user._id,
                email: user.email,
                // Adicione outros dados do usuário que queira enviar para o frontend
            }
        });

    } catch (error) {
        console.error("Erro no endpoint /api/auth/login:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao tentar fazer login.' });
    }
});

const TMDB_API_KEY = process.env.TMDB_API_KEY;
const TMDB_BASE_URL = 'https://api.themoviedb.org/3';

// Rota para buscar filmes populares
app.get('/api/tmdb/popular', async (req, res) => {
    if (!TMDB_API_KEY) {
        return res.status(500).json({ message: 'Chave da API do TMDB não configurada no servidor.' });
    }
    try {
        const response = await axios.get(`${TMDB_BASE_URL}/movie/popular`, {
            params: {
                api_key: TMDB_API_KEY,
                language: 'pt-BR', // Para resultados em português
                page: 1
            }
        });
        res.json(response.data.results); // Envia a lista de filmes populares
    } catch (error) {
        console.error('Erro ao buscar filmes populares do TMDB:', error.response ? error.response.data : error.message);
        res.status(error.response ? error.response.status : 500).json({ message: 'Erro ao buscar filmes populares.' });
    }
});

// Rota para buscar filmes em breve (Upcoming)
app.get('/api/tmdb/upcoming', async (req, res) => {
    if (!TMDB_API_KEY) {
        return res.status(500).json({ message: 'Chave da API do TMDB não configurada no servidor.' });
    }
    try {
        const response = await axios.get(`${TMDB_BASE_URL}/movie/upcoming`, {
            params: {
                api_key: TMDB_API_KEY,
                language: 'pt-BR',
                page: 1
            }
        });
        res.json(response.data.results);
    } catch (error) {
        console.error('Erro ao buscar filmes em breve do TMDB:', error.response ? error.response.data : error.message);
        res.status(error.response ? error.response.status : 500).json({ message: 'Erro ao buscar filmes em breve.' });
    }
});

// Rota para um filme em destaque (ex: o mais recente dos "Now Playing")
app.get('/api/tmdb/featured', async (req, res) => {
    if (!TMDB_API_KEY) {
        return res.status(500).json({ message: 'Chave da API do TMDB não configurada no servidor.' });
    }
    try {
        const response = await axios.get(`${TMDB_BASE_URL}/movie/now_playing`, {
            params: {
                api_key: TMDB_API_KEY,
                language: 'pt-BR',
                page: 1
            }
        });
        // Pega o primeiro filme da lista como destaque, por exemplo
        if (response.data.results && response.data.results.length > 0) {
            res.json(response.data.results[0]);
        } else {
            res.status(404).json({ message: 'Nenhum filme em destaque encontrado.' });
        }
    } catch (error) {
        console.error('Erro ao buscar filme em destaque do TMDB:', error.response ? error.response.data : error.message);
        res.status(error.response ? error.response.status : 500).json({ message: 'Erro ao buscar filme em destaque.' });
    }
});


app.get('/api/tmdb/movie/:movieId', async (req, res) => {
    const { movieId } = req.params; // Pega o movieId da URL

    if (!TMDB_API_KEY) {
        console.error("Chave da API do TMDB não configurada no servidor ao buscar detalhes do filme.");
        return res.status(500).json({ message: 'Chave da API do TMDB não configurada no servidor.' });
    }

    if (!movieId) {
        return res.status(400).json({ message: 'O ID do filme é obrigatório.' });
    }

    try {
        // Faz a requisição para o endpoint de detalhes do filme no TMDB
        // Adicionamos append_to_response=credits para buscar informações do elenco (cast)
        const response = await axios.get(`${TMDB_BASE_URL}/movie/${movieId}`, {
            params: {
                api_key: TMDB_API_KEY,
                language: 'pt-BR',
                append_to_response: 'credits,videos,images,release_dates,watch/providers' // Adiciona mais dados
            }
        });
        console.log(`Detalhes do filme ${movieId} buscados com sucesso do TMDB.`);
        res.json(response.data); // Envia todos os dados do filme

    } catch (error) {
        console.error(`Erro ao buscar detalhes do filme ${movieId} do TMDB:`, error.response ? error.response.data : error.message);
        
        if (error.response) {
            // Se o TMDB retornou um erro específico (ex: 404 Not Found)
            res.status(error.response.status).json({ 
                message: `Erro ao buscar detalhes do filme no TMDB: ${error.response.data.status_message || error.message}`,
                tmdb_status_code: error.response.data.status_code 
            });
        } else {
            // Erro de rede ou outro erro antes de receber resposta do TMDB
            res.status(500).json({ message: `Erro interno do servidor ao buscar detalhes do filme: ${error.message}` });
        }
    }
});



// 7. Iniciar o Servidor
app.listen(PORT, () => {
    console.log(`Servidor backend rodando na porta ${PORT}`);
    console.log(`Acesse em http://localhost:${PORT}`);
});