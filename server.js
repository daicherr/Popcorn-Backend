const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const axios = require('axios');

require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5001;

app.use(cors());
app.use(express.json());

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

// Nome padrão para a Watchlist do usuário
const DEFAULT_WATCHLIST_NAME = "Quero Ver";

// --- SCHEMAS ---
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

const reviewSchema = new mongoose.Schema({
    movieId: {
        type: String,
        required: true,
        index: true
    },
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: 'User',
        index: true // Importante para buscar/contar reviews por usuário
    },
    userEmail: {
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
    tags: {
        type: [String],
        default: []
    },
    isSpoiler: {
        type: Boolean,
        default: false
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

reviewSchema.index({ movieId: 1, userId: 1 }, { unique: true }); // Garante que um usuário só pode avaliar um filme uma vez

const Review = mongoose.model('Review', reviewSchema);

const movieItemSchema = new mongoose.Schema({
    tmdbId: { type: String, required: true },
    title: { type: String, required: true },
    posterPath: { type: String }, // Opcional, mas recomendado
    addedAt: { type: Date, default: Date.now }
}, { _id: false }); // _id: false para subdocumentos se não precisar de IDs individuais para eles

const userListSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, "O nome da lista é obrigatório."],
        trim: true,
        maxlength: [100, "O nome da lista não pode exceder 100 caracteres."]
    },
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: 'User',
        index: true
    },
    movies: [movieItemSchema],
    isPublic: { type: Boolean, default: false },
    description: {
        type: String,
        trim: true,
        maxlength: [500, "A descrição não pode exceder 500 caracteres."]
    },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

userListSchema.pre('save', function(next) {
    this.updatedAt = Date.now();
    next();
});

// Garante que um usuário não tenha múltiplas listas com o mesmo nome.
userListSchema.index({ userId: 1, name: 1 }, { unique: true });

const UserList = mongoose.model('UserList', userListSchema);

// --- MIDDLEWARE DE PROTEÇÃO (protect) ---
const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        try {
            token = req.headers.authorization.split(' ')[1];
            const JWT_SECRET = process.env.JWT_SECRET;
            if (!JWT_SECRET) {
                console.error("JWT_SECRET não definido no .env");
                throw new Error('Configuração de autenticação inválida no servidor.');
            }
            const decoded = jwt.verify(token, JWT_SECRET);
            req.user = await User.findById(decoded.userId).select('-password');
            if (!req.user) {
                return res.status(401).json({ message: 'Usuário não encontrado para este token.' });
            }
            next();
        } catch (error) {
            if (error.name === 'JsonWebTokenError') return res.status(401).json({ message: 'Token inválido.' });
            if (error.name === 'TokenExpiredError') return res.status(401).json({ message: 'Token expirado.' });
            console.error("Erro na autenticação do token:", error.message);
            return res.status(401).json({ message: 'Não autorizado, falha no token.' });
        }
    }
    if (!token) {
        res.status(401).json({ message: 'Não autorizado, nenhum token fornecido.' });
    }
};

// --- FUNÇÃO AUXILIAR PARA WATCHLIST ---
async function getOrCreateWatchlist(userId) {
    let watchlist = await UserList.findOne({ userId, name: DEFAULT_WATCHLIST_NAME });
    if (!watchlist) {
        watchlist = new UserList({
            name: DEFAULT_WATCHLIST_NAME,
            userId,
            description: "Filmes que desejo assistir.",
            isPublic: false, // Watchlist é privada por padrão
            movies: []
        });
        await watchlist.save();
    }
    return watchlist;
}


// --- ROTAS DE AUTENTICAÇÃO ---
app.post('/api/auth/register', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Por favor, forneça email e senha.' });
    if (password.length < 6) return res.status(400).json({ message: 'A senha deve ter pelo menos 6 caracteres.' });
    try {
        const existingUser = await User.findOne({ email: email.toLowerCase() });
        if (existingUser) return res.status(400).json({ message: 'Este email já está em uso.' });
        const newUser = new User({ email, password });
        await newUser.save();
        res.status(201).json({ message: 'Usuário cadastrado com sucesso!', userId: newUser._id });
    } catch (error) {
        if (error.code === 11000) return res.status(400).json({ message: 'Este email já está em uso (erro de duplicidade).' });
        if (error.name === 'ValidationError') {
            const messages = Object.values(error.errors).map(val => val.message);
            return res.status(400).json({ message: messages.join(', ') });
        }
        console.error("Erro no registro:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao tentar cadastrar o usuário.' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Por favor, forneça email e senha.' });
    try {
        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) return res.status(401).json({ message: 'Email ou senha inválidos.' });
        const isMatch = await user.comparePassword(password);
        if (!isMatch) return res.status(401).json({ message: 'Email ou senha inválidos.' });
        const JWT_SECRET = process.env.JWT_SECRET;
        if (!JWT_SECRET) return res.status(500).json({ message: "Erro de configuração do servidor (segredo JWT)." });
        const tokenPayload = { userId: user._id, email: user.email };
        const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }); // Aumentei a expiração para 7 dias
        res.status(200).json({
            message: 'Login bem-sucedido!',
            token: token,
            user: { id: user._id, email: user.email }
        });
    } catch (error) {
        console.error("Erro no login:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao tentar fazer login.' });
    }
});

// --- ROTAS TMDB ---
const TMDB_API_KEY = process.env.TMDB_API_KEY;
const TMDB_BASE_URL = 'https://api.themoviedb.org/3';

app.get('/api/tmdb/popular', async (req, res) => {
    if (!TMDB_API_KEY) return res.status(500).json({ message: 'Chave da API do TMDB não configurada no servidor.' });
    try {
        const response = await axios.get(`${TMDB_BASE_URL}/movie/popular`, { params: { api_key: TMDB_API_KEY, language: 'pt-BR', page: 1 } });
        res.json(response.data.results);
    } catch (error) { res.status(error.response ? error.response.status : 500).json({ message: 'Erro ao buscar filmes populares.' }); }
});

app.get('/api/tmdb/upcoming', async (req, res) => {
    if (!TMDB_API_KEY) return res.status(500).json({ message: 'Chave da API do TMDB não configurada no servidor.' });
    try {
        const response = await axios.get(`${TMDB_BASE_URL}/movie/upcoming`, { params: { api_key: TMDB_API_KEY, language: 'pt-BR', page: 1 } });
        res.json(response.data.results);
    } catch (error) { res.status(error.response ? error.response.status : 500).json({ message: 'Erro ao buscar filmes em breve.' }); }
});

app.get('/api/tmdb/featured', async (req, res) => {
    if (!TMDB_API_KEY) return res.status(500).json({ message: 'Chave da API do TMDB não configurada no servidor.' });
    try {
        const response = await axios.get(`${TMDB_BASE_URL}/movie/now_playing`, { params: { api_key: TMDB_API_KEY, language: 'pt-BR', page: 1 } });
        if (response.data.results && response.data.results.length > 0) res.json(response.data.results[Math.floor(Math.random() * Math.min(response.data.results.length, 10))]); // Pega um aleatório dos 10 primeiros
        else res.status(404).json({ message: 'Nenhum filme em destaque encontrado.' });
    } catch (error) { res.status(error.response ? error.response.status : 500).json({ message: 'Erro ao buscar filme em destaque.' }); }
});

app.get('/api/tmdb/movie/:movieId', async (req, res) => {
    const { movieId } = req.params;
    if (!TMDB_API_KEY) return res.status(500).json({ message: 'Chave da API do TMDB não configurada no servidor.' });
    if (!movieId) return res.status(400).json({ message: 'O ID do filme é obrigatório.' });
    try {
        const response = await axios.get(`${TMDB_BASE_URL}/movie/${movieId}`, { params: { api_key: TMDB_API_KEY, language: 'pt-BR', append_to_response: 'credits,videos,images,release_dates,watch/providers' } });
        res.json(response.data);
    } catch (error) {
        if (error.response) res.status(error.response.status).json({ message: `Erro ao buscar detalhes do filme no TMDB: ${error.response.data.status_message || error.message}`, tmdb_status_code: error.response.data.status_code });
        else res.status(500).json({ message: `Erro interno do servidor ao buscar detalhes do filme: ${error.message}` });
    }
});


// --- ROTAS DE REVIEWS ---
app.post('/api/reviews/:movieId', protect, async (req, res) => {
    const { movieId } = req.params;
    const { rating, reviewText, tags, isSpoiler } = req.body;
    const userId = req.user._id; const userEmail = req.user.email;

    if (rating == null || typeof rating !== 'number' || rating < 0.5 || rating > 5) return res.status(400).json({ message: "A nota (rating) é obrigatória e deve ser um número entre 0.5 e 5." });
    // Adicione outras validações se necessário (ex: reviewText não ser apenas espaços)

    try {
        const reviewData = { rating, reviewText: reviewText || '', tags: tags || [], isSpoiler: isSpoiler || false, updatedAt: Date.now() };
        // Usar findOneAndUpdate com upsert: true para criar se não existir, ou atualizar se existir.
        const updatedOrNewReview = await Review.findOneAndUpdate(
            { movieId, userId }, // Critério de busca
            { ...reviewData, userEmail }, // Dados para atualizar ou inserir (garante que userEmail esteja presente)
            { new: true, upsert: true, runValidators: true, setDefaultsOnInsert: true } // Opções
        );
        // Verifica se o documento foi criado ou atualizado para enviar o status code apropriado
        const statusCode = updatedOrNewReview.createdAt.getTime() === updatedOrNewReview.updatedAt.getTime() && mongoose.Types.ObjectId(updatedOrNewReview._id).getTimestamp().getTime() === updatedOrNewReview.updatedAt.getTime() ? 201 : 200;
        const message = statusCode === 201 ? "Crítica adicionada com sucesso!" : "Crítica atualizada com sucesso!";
        
        res.status(statusCode).json({ message, review: updatedOrNewReview });

    } catch (error) {
        if (error.name === 'ValidationError') { const messages = Object.values(error.errors).map(val => val.message); return res.status(400).json({ message: messages.join(', ') }); }
        console.error("Erro ao salvar review:", error);
        res.status(500).json({ message: "Erro interno do servidor ao salvar a crítica." });
    }
});

app.get('/api/reviews/:movieId', async (req, res) => {
    const { movieId } = req.params;
    try {
        const reviews = await Review.find({ movieId }).sort({ createdAt: -1 }).populate('userId', 'email'); // Adicionado populate para exemplo, remova se não quiser o email do user
        res.status(200).json(reviews);
    } catch (error) { res.status(500).json({ message: "Erro interno do servidor ao buscar as críticas." }); }
});

app.get('/api/movies/:movieId/stats', async (req, res) => {
    const { movieId } = req.params;
    try {
        const reviews = await Review.find({ movieId });
        if (reviews.length === 0) return res.status(200).json({ averageRating: 0, reviewCount: 0 });
        const totalRating = reviews.reduce((acc, review) => acc + review.rating, 0);
        const averageRating = totalRating / reviews.length;
        res.status(200).json({ averageRating: parseFloat(averageRating.toFixed(1)), reviewCount: reviews.length });
    } catch (error) { res.status(500).json({ message: "Erro ao calcular a nota média." }); }
});

app.get('/api/reviews/user/:userId/count', protect, async (req, res) => {
    const { userId } = req.params;
    if (req.user._id.toString() !== userId) {
        return res.status(403).json({ message: "Não autorizado a acessar estatísticas deste usuário." });
    }
    try {
        const count = await Review.countDocuments({ userId: userId });
        res.status(200).json({ count });
    } catch (error) {
        console.error('Erro ao contar avaliações do usuário:', error);
        res.status(500).json({ message: "Erro interno do servidor ao contar as avaliações." });
    }
});


// --- ROTAS DE LISTAS DE USUÁRIOS (UserList) ---
app.post('/api/lists', protect, async (req, res) => {
    const { name, description, isPublic } = req.body; const userId = req.user._id;
    if (!name || typeof name !== 'string' || name.trim() === '') return res.status(400).json({ message: "O nome da lista é obrigatório." });
    try {
        const newList = new UserList({ name: name.trim(), userId, description: description || '', isPublic: isPublic || false, movies: [] });
        const savedList = await newList.save();
        res.status(201).json(savedList);
    } catch (error) {
        if (error.code === 11000) { return res.status(400).json({ message: `Você já possui uma lista com o nome "${name.trim()}".` });}
        if (error.name === 'ValidationError') { const messages = Object.values(error.errors).map(val => val.message); return res.status(400).json({ message: messages.join(', ') });}
        res.status(500).json({ message: "Erro ao criar a lista." });
    }
});

app.get('/api/lists', protect, async (req, res) => { // Busca todas as listas do usuário logado
    try {
        const lists = await UserList.find({ userId: req.user._id }).sort({ updatedAt: -1 });
        res.status(200).json(lists);
    } catch (error) { res.status(500).json({ message: "Erro ao buscar as listas." }); }
});

app.get('/api/lists/:listId', protect, async (req, res) => { // Busca uma lista específica pelo ID
    try {
        const list = await UserList.findOne({ _id: req.params.listId, userId: req.user._id });
        if (!list) return res.status(404).json({ message: 'Lista não encontrada ou não pertence a este usuário.' });
        res.status(200).json(list);
    } catch (error) {
        if (error.kind === 'ObjectId') return res.status(400).json({ message: 'ID da lista inválido.' });
        res.status(500).json({ message: 'Erro ao buscar detalhes da lista.' });
    }
});

app.put('/api/lists/:listId', protect, async (req, res) => { // Atualiza uma lista
    const { name, description, isPublic } = req.body;
    const { listId } = req.params;
    const userId = req.user._id;

    if (!name || typeof name !== 'string' || name.trim() === '') return res.status(400).json({ message: "O nome da lista é obrigatório." });
    try {
        const list = await UserList.findOne({ _id: listId, userId });
        if (!list) return res.status(404).json({ message: 'Lista não encontrada ou não pertence a este usuário.' });

        if (name.trim().toLowerCase() !== list.name.toLowerCase()) { // Verifica se o nome foi alterado
            const existingListWithNewName = await UserList.findOne({ userId, name: name.trim(), _id: { $ne: listId } }); // Exclui a lista atual da verificação
            if (existingListWithNewName) {
                return res.status(400).json({ message: `Você já possui outra lista com o nome "${name.trim()}".` });
            }
        }
        
        list.name = name.trim();
        list.description = description != null ? description.trim() : (list.description || ''); // Mantém a descrição antiga se não fornecida
        list.isPublic = isPublic != null ? isPublic : list.isPublic; // Mantém o status antigo se não fornecido
        list.updatedAt = Date.now();
        const updatedList = await list.save();
        res.status(200).json(updatedList);
    } catch (error) {
        if (error.kind === 'ObjectId') return res.status(400).json({ message: 'ID da lista inválido.' });
        if (error.name === 'ValidationError') { const messages = Object.values(error.errors).map(val => val.message); return res.status(400).json({ message: messages.join(', ') });}
        res.status(500).json({ message: 'Erro ao atualizar a lista.' });
    }
});

app.delete('/api/lists/:listId', protect, async (req, res) => { // Deleta uma lista
    try {
        const list = await UserList.findOneAndDelete({ _id: req.params.listId, userId: req.user._id });
        if (!list) return res.status(404).json({ message: 'Lista não encontrada ou não pertence a este usuário.' });
        res.status(200).json({ message: 'Lista deletada com sucesso.' });
    } catch (error) {
        if (error.kind === 'ObjectId') return res.status(400).json({ message: 'ID da lista inválido.' });
        res.status(500).json({ message: 'Erro ao deletar a lista.' });
    }
});

app.post('/api/lists/:listId/movies', protect, async (req, res) => { // Adiciona filme a uma lista
    const { tmdbId, title, posterPath } = req.body;
    if (!tmdbId || !title) return res.status(400).json({ message: 'ID do filme (tmdbId) e título são obrigatórios.' });
    try {
        const list = await UserList.findOne({ _id: req.params.listId, userId: req.user._id });
        if (!list) return res.status(404).json({ message: 'Lista não encontrada.' });
        if (list.movies.find(movie => movie.tmdbId === tmdbId.toString())) {
            return res.status(400).json({ message: 'Este filme já está na lista.' });
        }
        list.movies.push({ tmdbId: tmdbId.toString(), title, posterPath: posterPath || '' });
        list.updatedAt = Date.now();
        await list.save();
        res.status(200).json(list);
    } catch (error) {
        if (error.kind === 'ObjectId') return res.status(400).json({ message: 'ID da lista inválido.' });
        res.status(500).json({ message: 'Erro ao adicionar filme à lista.' });
    }
});

app.delete('/api/lists/:listId/movies/:tmdbMovieId', protect, async (req, res) => { // Remove filme de uma lista
    try {
        const list = await UserList.findOne({ _id: req.params.listId, userId: req.user._id });
        if (!list) return res.status(404).json({ message: 'Lista não encontrada.' });
        const movieIndex = list.movies.findIndex(movie => movie.tmdbId === req.params.tmdbMovieId.toString());
        if (movieIndex === -1) return res.status(404).json({ message: 'Filme não encontrado nesta lista.' });
        list.movies.splice(movieIndex, 1);
        list.updatedAt = Date.now();
        await list.save();
        res.status(200).json(list);
    } catch (error) {
        if (error.kind === 'ObjectId') return res.status(400).json({ message: 'ID da lista ou do filme inválido.' });
        res.status(500).json({ message: 'Erro ao remover filme da lista.' });
    }
});


// --- ROTAS ESPECÍFICAS PARA WATCHLIST ---
app.get('/api/watchlist', protect, async (req, res) => {
    try {
        const watchlist = await getOrCreateWatchlist(req.user._id);
        res.status(200).json(watchlist);
    } catch (error) {
        console.error("Erro ao buscar watchlist:", error);
        res.status(500).json({ message: "Erro ao buscar sua watchlist." });
    }
});

app.post('/api/watchlist/movies', protect, async (req, res) => {
    const { tmdbId, title, posterPath } = req.body;
    if (!tmdbId || !title) {
        return res.status(400).json({ message: 'ID do filme (tmdbId) e título são obrigatórios.' });
    }
    try {
        const watchlist = await getOrCreateWatchlist(req.user._id);
        if (watchlist.movies.find(movie => movie.tmdbId === tmdbId.toString())) {
             return res.status(200).json({ message: 'Filme já está na sua watchlist.', list: watchlist });
        }
        watchlist.movies.push({ tmdbId: tmdbId.toString(), title, posterPath: posterPath || '' });
        watchlist.updatedAt = Date.now();
        await watchlist.save();
        res.status(201).json({ message: 'Filme adicionado à sua watchlist.', list: watchlist });
    } catch (error) {
        console.error("Erro ao adicionar filme à watchlist:", error);
        res.status(500).json({ message: 'Erro ao adicionar filme à sua watchlist.' });
    }
});

app.delete('/api/watchlist/movies/:tmdbMovieId', protect, async (req, res) => {
    const { tmdbMovieId } = req.params;
    try {
        const watchlist = await getOrCreateWatchlist(req.user._id);
        const movieIndex = watchlist.movies.findIndex(movie => movie.tmdbId === tmdbMovieId.toString());
        if (movieIndex === -1) {
            return res.status(404).json({ message: 'Filme não encontrado na sua watchlist.' });
        }
        watchlist.movies.splice(movieIndex, 1);
        watchlist.updatedAt = Date.now();
        await watchlist.save();
        res.status(200).json({ message: 'Filme removido da sua watchlist.', list: watchlist });
    } catch (error) {
        console.error("Erro ao remover filme da watchlist:", error);
        res.status(500).json({ message: 'Erro ao remover filme da sua watchlist.' });
    }
});

app.get('/api/watchlist/movies/:tmdbMovieId/status', protect, async (req, res) => {
    const { tmdbMovieId } = req.params;
    try {
        const watchlist = await UserList.findOne({ userId: req.user._id, name: DEFAULT_WATCHLIST_NAME });
        let isInWatchlist = false;
        if (watchlist) {
            isInWatchlist = watchlist.movies.some(movie => movie.tmdbId === tmdbMovieId.toString());
        }
        res.status(200).json({ isInWatchlist });
    } catch (error) {
        console.error("Erro ao verificar status do filme na watchlist:", error);
        res.status(500).json({ message: 'Erro ao verificar status do filme na sua watchlist.' });
    }
});


// --- INICIALIZAÇÃO DO SERVIDOR ---
app.listen(PORT, () => {
    console.log(`Servidor backend rodando na porta ${PORT}`);
    console.log(`Acesse em http://localhost:${PORT} (se local) ou no seu URL do Render.`);
});