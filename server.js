// server.js - Arquivo principal do seu backend

// 1. Importar dependências
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const axios = require('axios');

require('dotenv').config();

// 2. Inicializar a aplicação Express
const app = express();
const PORT = process.env.PORT || 5001;

// 3. Middlewares
app.use(cors());
app.use(express.json());

// 4. Conexão com o MongoDB Atlas
const MONGO_URI = process.env.MONGO_ATLAS_URI;

if (!MONGO_URI) {
    console.error("ERRO: String de conexão do MongoDB Atlas (MONGO_ATLAS_URI) não definida no arquivo .env");
    process.exit(1);
}

mongoose.connect(MONGO_URI)
.then(() => console.log('Conectado com sucesso ao MongoDB Atlas!'))
.catch(err => {
    console.error('Erro ao conectar ao MongoDB Atlas:', err);
    process.exit(1);
});

// 5. Schema e Model do Usuário
const userSchema = new mongoose.Schema({
    email: {
        type: String,
        required: [true, "O email é obrigatório"],
        unique: true,
        trim: true,
        lowercase: true,
        match: [/\S+@\S+\.\S+/, 'Por favor, use um email válido.']
    },
    password: {
        type: String,
        required: [true, "A senha é obrigatória"],
        minlength: [6, "A senha deve ter pelo menos 6 caracteres"]
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    try {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (error) {
        next(error);
    }
});

userSchema.methods.comparePassword = async function(candidatePassword) {
    return bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', userSchema);

// Schema e Model da Review/Crítica
const reviewSchema = new mongoose.Schema({
    movieId: {
        type: String,
        required: true,
        index: true
    },
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: 'User'
    },
    userEmail: { // Para exibir na review sem precisar de populate sempre
        type: String,
        required: true,
    },
    rating: {
        type: Number,
        required: [true, "A nota é obrigatória."],
        min: 0.5,
        max: 5
    },
    reviewText: {
        type: String,
        trim: true,
        maxlength: [5000, "A crítica não pode exceder 5000 caracteres."]
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
});

reviewSchema.pre('save', function(next) {
    this.updatedAt = Date.now();
    next();
});

reviewSchema.index({ movieId: 1, userId: 1 }, { unique: true }); // Um usuário por filme

const Review = mongoose.model('Review', reviewSchema);


// Middleware de Autenticação (protect)
const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        try {
            token = req.headers.authorization.split(' ')[1];
            const JWT_SECRET = process.env.JWT_SECRET;
            if (!JWT_SECRET) {
                console.error("ERRO: Segredo JWT (JWT_SECRET) não definido no .env para authMiddleware.");
                throw new Error('Configuração de autenticação inválida no servidor.');
            }
            const decoded = jwt.verify(token, JWT_SECRET);
            req.user = await User.findById(decoded.userId).select('-password');
            if (!req.user) {
                return res.status(401).json({ message: 'Usuário não encontrado para este token.' });
            }
            next();
        } catch (error) {
            console.error('Erro na autenticação do token:', error.message);
            if (error.name === 'JsonWebTokenError') {
                return res.status(401).json({ message: 'Token inválido.' });
            }
            if (error.name === 'TokenExpiredError') {
                return res.status(401).json({ message: 'Token expirado.' });
            }
            return res.status(401).json({ message: 'Não autorizado, falha no token.' });
        }
    }
    if (!token) {
        res.status(401).json({ message: 'Não autorizado, nenhum token fornecido.' });
    }
};

// 6. Rotas da API

// Rotas de Autenticação (já existentes)
app.post('/api/auth/register', async (req, res) => {
    // ... (seu código de registro existente, sem alterações)
    console.log("Recebida requisição POST em /api/auth/register");
    console.log("Corpo da requisição:", req.body);

    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Por favor, forneça email e senha.' });
    }
    if (password.length < 6) {
        return res.status(400).json({ message: 'A senha deve ter pelo menos 6 caracteres.' });
    }

    try {
        const existingUser = await User.findOne({ email: email.toLowerCase() });
        if (existingUser) {
            console.log("Tentativa de cadastro com email já existente:", email);
            return res.status(400).json({ message: 'Este email já está em uso.' });
        }

        const newUser = new User({ email, password });
        await newUser.save();

        console.log("Novo usuário cadastrado com sucesso:", newUser.email, newUser._id);
        res.status(201).json({ message: 'Usuário cadastrado com sucesso!', userId: newUser._id });

    } catch (error) {
        console.error("Erro no endpoint /api/auth/register:", error);
        if (error.code === 11000) {
             return res.status(400).json({ message: 'Este email já está em uso (erro de duplicidade).' });
        }
        if (error.name === 'ValidationError') {
            const messages = Object.values(error.errors).map(val => val.message);
            return res.status(400).json({ message: messages.join(', ') });
        }
        res.status(500).json({ message: 'Erro interno do servidor ao tentar cadastrar o usuário.' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    // ... (seu código de login existente, sem alterações)
    console.log("Recebida requisição POST em /api/auth/login");
    console.log("Corpo da requisição:", req.body);

    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Por favor, forneça email e senha.' });
    }

    try {
        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) {
            console.log("Tentativa de login com email não encontrado:", email);
            return res.status(401).json({ message: 'Email ou senha inválidos.' });
        }

        const isMatch = await user.comparePassword(password);
        if (!isMatch) {
            console.log("Tentativa de login com senha incorreta para o email:", email);
            return res.status(401).json({ message: 'Email ou senha inválidos.' });
        }

        const JWT_SECRET = process.env.JWT_SECRET;
        if (!JWT_SECRET) {
            console.error("ERRO: Segredo JWT (JWT_SECRET) não definido no arquivo .env");
            return res.status(500).json({ message: "Erro de configuração do servidor (segredo JWT)." });
        }

        const tokenPayload = { userId: user._id, email: user.email };
        const token = jwt.sign(
            tokenPayload,
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        console.log("Login bem-sucedido para o usuário:", user.email, user._id);
        res.status(200).json({
            message: 'Login bem-sucedido!',
            token: token,
            user: {
                id: user._id,
                email: user.email,
            }
        });

    } catch (error) {
        console.error("Erro no endpoint /api/auth/login:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao tentar fazer login.' });
    }
});

// Rotas do TMDB (já existentes)
const TMDB_API_KEY = process.env.TMDB_API_KEY;
const TMDB_BASE_URL = 'https://api.themoviedb.org/3';

app.get('/api/tmdb/popular', async (req, res) => {
    // ... (seu código existente)
    if (!TMDB_API_KEY) {
        return res.status(500).json({ message: 'Chave da API do TMDB não configurada no servidor.' });
    }
    try {
        const response = await axios.get(`${TMDB_BASE_URL}/movie/popular`, {
            params: { api_key: TMDB_API_KEY, language: 'pt-BR', page: 1 }
        });
        res.json(response.data.results);
    } catch (error) {
        console.error('Erro ao buscar filmes populares do TMDB:', error.response ? error.response.data : error.message);
        res.status(error.response ? error.response.status : 500).json({ message: 'Erro ao buscar filmes populares.' });
    }
});

app.get('/api/tmdb/upcoming', async (req, res) => {
    // ... (seu código existente)
    if (!TMDB_API_KEY) {
        return res.status(500).json({ message: 'Chave da API do TMDB não configurada no servidor.' });
    }
    try {
        const response = await axios.get(`${TMDB_BASE_URL}/movie/upcoming`, {
            params: { api_key: TMDB_API_KEY, language: 'pt-BR', page: 1 }
        });
        res.json(response.data.results);
    } catch (error) {
        console.error('Erro ao buscar filmes em breve do TMDB:', error.response ? error.response.data : error.message);
        res.status(error.response ? error.response.status : 500).json({ message: 'Erro ao buscar filmes em breve.' });
    }
});

app.get('/api/tmdb/featured', async (req, res) => {
    // ... (seu código existente)
    if (!TMDB_API_KEY) {
        return res.status(500).json({ message: 'Chave da API do TMDB não configurada no servidor.' });
    }
    try {
        const response = await axios.get(`${TMDB_BASE_URL}/movie/now_playing`, {
            params: { api_key: TMDB_API_KEY, language: 'pt-BR', page: 1 }
        });
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
    // ... (seu código existente para detalhes do filme)
    const { movieId } = req.params;
    if (!TMDB_API_KEY) {
        console.error("Chave da API do TMDB não configurada no servidor ao buscar detalhes do filme.");
        return res.status(500).json({ message: 'Chave da API do TMDB não configurada no servidor.' });
    }
    if (!movieId) {
        return res.status(400).json({ message: 'O ID do filme é obrigatório.' });
    }
    try {
        const response = await axios.get(`${TMDB_BASE_URL}/movie/${movieId}`, {
            params: {
                api_key: TMDB_API_KEY,
                language: 'pt-BR',
                append_to_response: 'credits,videos,images,release_dates,watch/providers'
            }
        });
        console.log(`Detalhes do filme ${movieId} buscados com sucesso do TMDB.`);
        res.json(response.data);
    } catch (error) {
        console.error(`Erro ao buscar detalhes do filme ${movieId} do TMDB:`, error.response ? error.response.data : error.message);
        if (error.response) {
            res.status(error.response.status).json({ 
                message: `Erro ao buscar detalhes do filme no TMDB: ${error.response.data.status_message || error.message}`,
                tmdb_status_code: error.response.data.status_code 
            });
        } else {
            res.status(500).json({ message: `Erro interno do servidor ao buscar detalhes do filme: ${error.message}` });
        }
    }
});


// --- NOVAS ROTAS PARA REVIEWS E NOTAS ---

// ROTA PARA CRIAR/ATUALIZAR UMA REVIEW/AVALIAÇÃO PARA UM FILME
// Requer autenticação
app.post('/api/reviews/:movieId', protect, async (req, res) => {
    const { movieId } = req.params;
    const { rating, reviewText } = req.body;
    const userId = req.user._id; 
    const userEmail = req.user.email;

    if (rating == null || typeof rating !== 'number') {
        return res.status(400).json({ message: "A nota (rating) é obrigatória e deve ser um número." });
    }
    if (rating < 0.5 || rating > 5) { 
        return res.status(400).json({ message: "A nota deve ser entre 0.5 e 5." });
    }
    if (reviewText && typeof reviewText !== 'string') {
        return res.status(400).json({ message: "O texto da crítica, se fornecido, deve ser uma string."});
    }


    try {
        const existingReview = await Review.findOne({ movieId, userId });

        if (existingReview) {
            existingReview.rating = rating;
            existingReview.reviewText = reviewText != null ? reviewText : existingReview.reviewText; // Permite limpar ou manter
            existingReview.updatedAt = Date.now();
            const updatedReview = await existingReview.save();
            console.log(`Review atualizada para o filme ${movieId} pelo usuário ${userEmail}`);
            return res.status(200).json({ message: "Crítica atualizada com sucesso!", review: updatedReview });
        } else {
            const newReview = new Review({
                movieId,
                userId,
                userEmail,
                rating,
                reviewText: reviewText || ''
            });
            const savedReview = await newReview.save();
            console.log(`Nova review criada para o filme ${movieId} pelo usuário ${userEmail}`);
            return res.status(201).json({ message: "Crítica adicionada com sucesso!", review: savedReview });
        }

    } catch (error) {
        console.error(`Erro ao salvar/atualizar review para o filme ${movieId} pelo usuário ${userEmail}:`, error);
        if (error.name === 'ValidationError') {
            const messages = Object.values(error.errors).map(val => val.message);
            return res.status(400).json({ message: messages.join(', ') });
        }
        if (error.code === 11000) { // Erro de índice único duplicado
            return res.status(409).json({ message: 'Você já enviou uma crítica para este filme.' });
        }
        res.status(500).json({ message: "Erro interno do servidor ao salvar a crítica." });
    }
});

// ROTA PARA BUSCAR TODAS AS REVIEWS DE UM FILME ESPECÍFICO
app.get('/api/reviews/:movieId', async (req, res) => {
    const { movieId } = req.params;

    try {
        const reviews = await Review.find({ movieId })
            .sort({ createdAt: -1 }) // Mais recentes primeiro
            // .populate('userId', 'email nomeDoCampoApelido'); // Se quiser trazer outros campos do User além do userEmail já salvo
        
        console.log(`Buscando reviews para o filme ${movieId}. Encontradas: ${reviews.length}`);
        res.status(200).json(reviews);

    } catch (error) {
        console.error(`Erro ao buscar reviews para o filme ${movieId}:`, error);
        res.status(500).json({ message: "Erro interno do servidor ao buscar as críticas." });
    }
});

// ROTA PARA BUSCAR AS ESTATÍSTICAS (NOTA MÉDIA E CONTAGEM) DE UM FILME
app.get('/api/movies/:movieId/stats', async (req, res) => {
    const { movieId } = req.params;

    try {
        const reviews = await Review.find({ movieId });
        
        if (reviews.length === 0) {
            console.log(`Nenhuma review encontrada para o filme ${movieId} para calcular estatísticas.`);
            return res.status(200).json({ averageRating: 0, reviewCount: 0, userHasReviewed: false, userRating: null });
        }

        const totalRating = reviews.reduce((acc, review) => acc + review.rating, 0);
        const averageRating = totalRating / reviews.length;
        
        let userHasReviewed = false;
        let userRating = null;

        // Se quisermos verificar se o usuário atual (se houver um token) já fez review
        // Isso requereria o middleware 'protect' ou uma versão opcional dele aqui.
        // Por simplicidade, vamos omitir essa parte por enquanto para esta rota pública de stats.
        // Se precisar, podemos adicionar depois.

        console.log(`Estatísticas para o filme ${movieId}: Média ${averageRating.toFixed(1)}, Total ${reviews.length}`);
        res.status(200).json({
            averageRating: parseFloat(averageRating.toFixed(1)),
            reviewCount: reviews.length,
            // userHasReviewed: userHasReviewed, // Adicionar se implementar verificação do usuário atual
            // userRating: userRating            // Adicionar se implementar verificação do usuário atual
        });

    } catch (error) {
        console.error(`Erro ao calcular estatísticas para o filme ${movieId}:`, error);
        res.status(500).json({ message: "Erro ao calcular a nota média." });
    }
});


// 7. Iniciar o Servidor
app.listen(PORT, () => {
    console.log(`Servidor backend rodando na porta ${PORT}`);
    console.log(`Acesse em http://localhost:${PORT}`);
});