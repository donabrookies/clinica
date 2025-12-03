// ============================================
// BACKEND CORRIGIDO PARA VERCEL
// ============================================

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@clinica.com';

module.exports = async (req, res) => {
    // Configurar CORS
    res.setHeader('Access-Control-Allow-Credentials', true);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
    
    // Lidar com preflight requests
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }
    
    // Extrair path
    const { method, url } = req;
    const path = url.split('?')[0];
    
    console.log(`[${method}] ${path}`); // Log para debug
    
    try {
        // Roteamento
        switch (path) {
            case '/':
            case '/api':
                return res.json({ 
                    api: 'Clinica Ficha Digital API', 
                    status: 'online', 
                    version: '1.0',
                    endpoints: [
                        'POST /api/login',
                        'POST /api/registrar',
                        'GET /api/me',
                        'PUT /api/orientacao/:id/lida',
                        'GET /api/admin/dashboard',
                        'GET /api/admin/pacientes',
                        'GET /api/admin/paciente/:id',
                        'POST /api/admin/novo-paciente',
                        'POST /api/admin/enviar-documento',
                        'POST /api/admin/enviar-orientacao',
                        'POST /api/admin/adicionar-foto',
                        'POST /api/admin/nova-consulta',
                        'GET /api/admin/consultas',
                        'GET /api/admin/orientacoes'
                    ]
                });
            
            case '/api/login':
                if (method === 'POST') return await handleLogin(req, res);
                break;
            
            case '/api/registrar':
                if (method === 'POST') return await handleRegister(req, res);
                break;
            
            case '/api/me':
                if (method === 'GET') return await handleGetMe(req, res);
                break;
            
            default:
                // Verificar rotas dinâmicas
                if (path.startsWith('/api/orientacao/') && path.endsWith('/lida') && method === 'PUT') {
                    return await handleMarcarLida(req, res, path);
                }
                
                if (path === '/api/admin/dashboard' && method === 'GET') {
                    return await handleAdminDashboard(req, res);
                }
                
                if (path === '/api/admin/pacientes' && method === 'GET') {
                    return await handleAdminPacientes(req, res);
                }
                
                if (path.startsWith('/api/admin/paciente/') && method === 'GET') {
                    return await handleAdminPaciente(req, res, path);
                }
                
                if (path === '/api/admin/novo-paciente' && method === 'POST') {
                    return await handleAdminNovoPaciente(req, res);
                }
                
                if (path === '/api/admin/enviar-documento' && method === 'POST') {
                    return await handleEnviarDocumento(req, res);
                }
                
                if (path === '/api/admin/enviar-orientacao' && method === 'POST') {
                    return await handleEnviarOrientacao(req, res);
                }
                
                if (path === '/api/admin/adicionar-foto' && method === 'POST') {
                    return await handleAdicionarFoto(req, res);
                }
                
                if (path === '/api/admin/nova-consulta' && method === 'POST') {
                    return await handleNovaConsulta(req, res);
                }
                
                if (path === '/api/admin/consultas' && method === 'GET') {
                    return await handleAdminConsultas(req, res);
                }
                
                if (path === '/api/admin/orientacoes' && method === 'GET') {
                    return await handleAdminOrientacoes(req, res);
                }
                
                // Rota não encontrada
                return res.status(404).json({ 
                    error: 'Rota não encontrada',
                    path: path,
                    method: method
                });
        }
    } catch (error) {
        console.error('Erro no servidor:', error);
        return res.status(500).json({ 
            error: 'Erro interno do servidor',
            message: error.message 
        });
    }
};

// ========== FUNÇÕES AUXILIARES ==========

async function fetchSupabase(endpoint, options = {}) {
    const url = `${SUPABASE_URL}/rest/v1/${endpoint}`;
    console.log(`Fetching Supabase: ${url}`);
    
    const response = await fetch(url, {
        ...options,
        headers: {
            'Content-Type': 'application/json',
            'apikey': SUPABASE_KEY,
            'Authorization': `Bearer ${SUPABASE_KEY}`,
            ...options.headers
        }
    });
    
    if (!response.ok) {
        const error = await response.text();
        throw new Error(`Supabase error: ${response.status} - ${error}`);
    }
    
    return response.json();
}

async function authSupabase(endpoint, options = {}) {
    const url = `${SUPABASE_URL}/auth/v1/${endpoint}`;
    console.log(`Auth Supabase: ${url}`);
    
    const response = await fetch(url, {
        ...options,
        headers: {
            'Content-Type': 'application/json',
            'apikey': SUPABASE_KEY,
            ...options.headers
        }
    });
    
    if (!response.ok) {
        const error = await response.text();
        throw new Error(`Auth error: ${response.status} - ${error}`);
    }
    
    return response.json();
}

async function verifyToken(token) {
    try {
        const response = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
            headers: {
                'Authorization': `Bearer ${token}`,
                'apikey': SUPABASE_KEY
            }
        });
        
        if (!response.ok) {
            console.log(`Token verification failed: ${response.status}`);
            return null;
        }
        
        const data = await response.json();
        return data.user;
    } catch (error) {
        console.error('Token verification error:', error);
        return null;
    }
}

async function obterPacienteId(userId) {
    try {
        const [paciente] = await fetchSupabase(`pacientes?user_id=eq.${userId}&select=id`);
        return paciente ? paciente.id : null;
    } catch (error) {
        console.error('Erro ao obter paciente ID:', error);
        return null;
    }
}

async function verifyAdmin(req) {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) {
        console.log('Token ausente');
        return { valid: false, error: 'Token ausente' };
    }
    
    const user = await verifyToken(token);
    if (!user) {
        console.log('Token inválido');
        return { valid: false, error: 'Token inválido' };
    }
    
    if (user.email !== ADMIN_EMAIL) {
        console.log(`Acesso negado para: ${user.email}`);
        return { valid: false, error: 'Acesso negado. Apenas admin.' };
    }
    
    return { valid: true, user };
}

// ========== HANDLERS ==========

async function handleLogin(req, res) {
    console.log('Handling login');
    
    let body;
    try {
        body = await parseBody(req);
        console.log('Login body:', body);
    } catch (error) {
        return res.status(400).json({ error: 'Erro ao parsear body' });
    }
    
    const { email, password } = body;
    
    if (!email || !password) {
        return res.status(400).json({ error: 'Email e senha são obrigatórios' });
    }
    
    try {
        // Autenticar no Supabase
        const authData = await authSupabase('token?grant_type=password', {
            method: 'POST',
            body: JSON.stringify({ email, password })
        });
        
        console.log('Auth response:', authData.user ? 'Success' : 'Failed');
        
        if (!authData.user) {
            return res.status(401).json({ error: 'Credenciais inválidas' });
        }
        
        // Buscar paciente
        const pacientes = await fetchSupabase(`pacientes?user_id=eq.${authData.user.id}&select=*`);
        const paciente = pacientes[0] || null;
        
        return res.json({
            success: true,
            user: authData.user,
            paciente: paciente,
            token: authData.access_token
        });
    } catch (error) {
        console.error('Login error:', error);
        return res.status(400).json({ 
            error: 'Erro ao fazer login',
            details: error.message 
        });
    }
}

async function handleRegister(req, res) {
    console.log('Handling register');
    
    let body;
    try {
        body = await parseBody(req);
        console.log('Register body:', body);
    } catch (error) {
        return res.status(400).json({ error: 'Erro ao parsear body' });
    }
    
    const { email, password, nome, telefone, data_nascimento } = body;
    
    if (!email || !password || !nome) {
        return res.status(400).json({ error: 'Email, senha e nome são obrigatórios' });
    }
    
    try {
        // Registrar usuário
        const authData = await authSupabase('signup', {
            method: 'POST',
            body: JSON.stringify({ 
                email, 
                password, 
                data: { nome } 
            })
        });
        
        console.log('Signup response:', authData.user ? 'Success' : 'Failed');
        
        if (!authData.user) {
            return res.status(400).json({ error: 'Erro ao criar usuário' });
        }
        
        // Criar paciente
        await fetchSupabase('pacientes', {
            method: 'POST',
            body: JSON.stringify([{
                user_id: authData.user.id,
                nome,
                email,
                telefone,
                data_nascimento
            }])
        });
        
        return res.json({
            success: true,
            message: 'Registro realizado!',
            user: authData.user
        });
    } catch (error) {
        console.error('Register error:', error);
        return res.status(400).json({ 
            error: 'Erro ao registrar usuário',
            details: error.message 
        });
    }
}

async function handleGetMe(req, res) {
    console.log('Handling getMe');
    
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Token ausente' });
    
    const user = await verifyToken(token);
    if (!user) return res.status(401).json({ error: 'Token inválido' });
    
    const pacienteId = await obterPacienteId(user.id);
    if (!pacienteId) return res.status(404).json({ error: 'Paciente não encontrado' });
    
    try {
        // Buscar todos os dados em paralelo
        const [pacientes, consultas, documentos, fotos, orientacoes] = await Promise.all([
            fetchSupabase(`pacientes?user_id=eq.${user.id}&select=*`),
            fetchSupabase(`consultas?paciente_id=eq.${pacienteId}&select=*&order=data.desc`),
            fetchSupabase(`documentos?paciente_id=eq.${pacienteId}&select=*&order=created_at.desc`),
            fetchSupabase(`fotos?paciente_id=eq.${pacienteId}&select=*&order=data.desc`),
            fetchSupabase(`orientacoes?paciente_id=eq.${pacienteId}&select=*&order=created_at.desc`)
        ]);
        
        return res.json({
            paciente: pacientes[0] || null,
            consultas: consultas || [],
            documentos: documentos || [],
            fotos: fotos || [],
            orientacoes: orientacoes || []
        });
    } catch (error) {
        console.error('GetMe error:', error);
        return res.status(500).json({ 
            error: 'Erro ao buscar dados',
            details: error.message 
        });
    }
}

async function handleMarcarLida(req, res, path) {
    console.log('Handling marcarLida:', path);
    
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Token ausente' });
    
    const user = await verifyToken(token);
    if (!user) return res.status(401).json({ error: 'Token inválido' });
    
    const id = path.split('/')[3]; // /api/orientacao/{id}/lida
    
    try {
        await fetchSupabase(`orientacoes?id=eq.${id}`, {
            method: 'PATCH',
            body: JSON.stringify({ lida: true })
        });
        
        return res.json({ success: true });
    } catch (error) {
        console.error('MarcarLida error:', error);
        return res.status(500).json({ 
            error: 'Erro ao marcar como lida',
            details: error.message 
        });
    }
}

// ========== HANDLERS ADMIN ==========

async function handleAdminDashboard(req, res) {
    console.log('Handling admin dashboard');
    
    const admin = await verifyAdmin(req);
    if (!admin.valid) return res.status(403).json({ error: admin.error });
    
    try {
        // Buscar estatísticas
        const [pacientes, documentos, consultas, fotos] = await Promise.all([
            fetchSupabase('pacientes?select=count'),
            fetchSupabase('documentos?select=count'),
            fetchSupabase('consultas?select=count'),
            fetchSupabase('fotos?select=count')
        ]);
        
        // Atividade recente
        const orientacoes = await fetchSupabase('orientacoes?select=*,pacientes(nome)&order=created_at.desc&limit=10');
        
        return res.json({
            totalPacientes: pacientes[0]?.count || 0,
            totalDocumentos: documentos[0]?.count || 0,
            totalConsultas: consultas[0]?.count || 0,
            totalFotos: fotos[0]?.count || 0,
            atividade: orientacoes.map(o => ({
                titulo: `Orientação para ${o.pacientes?.nome || 'Paciente'}`,
                descricao: o.titulo,
                data: new Date(o.created_at).toLocaleDateString('pt-BR')
            }))
        });
    } catch (error) {
        console.error('Admin dashboard error:', error);
        return res.status(500).json({ 
            error: 'Erro ao buscar dashboard',
            details: error.message 
        });
    }
}

async function handleAdminPacientes(req, res) {
    console.log('Handling admin pacientes');
    
    const admin = await verifyAdmin(req);
    if (!admin.valid) return res.status(403).json({ error: admin.error });
    
    try {
        const pacientes = await fetchSupabase('pacientes?select=*&order=nome.asc');
        return res.json(pacientes);
    } catch (error) {
        console.error('Admin pacientes error:', error);
        return res.status(500).json({ 
            error: 'Erro ao buscar pacientes',
            details: error.message 
        });
    }
}

async function handleAdminPaciente(req, res, path) {
    console.log('Handling admin paciente:', path);
    
    const admin = await verifyAdmin(req);
    if (!admin.valid) return res.status(403).json({ error: admin.error });
    
    const id = path.split('/')[4]; // /api/admin/paciente/{id}
    
    try {
        const [paciente, consultas, documentos, fotos, orientacoes] = await Promise.all([
            fetchSupabase(`pacientes?id=eq.${id}&select=*`),
            fetchSupabase(`consultas?paciente_id=eq.${id}&select=*&order=data.desc&limit=10`),
            fetchSupabase(`documentos?paciente_id=eq.${id}&select=*&order=created_at.desc&limit=10`),
            fetchSupabase(`fotos?paciente_id=eq.${id}&select=*&order=data.desc&limit=10`),
            fetchSupabase(`orientacoes?paciente_id=eq.${id}&select=*&order=created_at.desc&limit=10`)
        ]);
        
        return res.json({
            paciente: paciente[0] || null,
            consultas: consultas || [],
            documentos: documentos || [],
            fotos: fotos || [],
            orientacoes: orientacoes || []
        });
    } catch (error) {
        console.error('Admin paciente error:', error);
        return res.status(500).json({ 
            error: 'Erro ao buscar paciente',
            details: error.message 
        });
    }
}

async function handleAdminNovoPaciente(req, res) {
    console.log('Handling admin novo paciente');
    
    const admin = await verifyAdmin(req);
    if (!admin.valid) return res.status(403).json({ error: admin.error });
    
    let body;
    try {
        body = await parseBody(req);
    } catch (error) {
        return res.status(400).json({ error: 'Erro ao parsear body' });
    }
    
    const { email, password, nome, telefone, data_nascimento } = body;
    
    if (!email || !password || !nome) {
        return res.status(400).json({ error: 'Email, senha e nome são obrigatórios' });
    }
    
    try {
        // Registrar usuário
        const authData = await authSupabase('signup', {
            method: 'POST',
            body: JSON.stringify({ email, password, data: { nome } })
        });
        
        if (!authData.user) {
            return res.status(400).json({ error: 'Erro ao criar usuário' });
        }
        
        // Criar paciente
        await fetchSupabase('pacientes', {
            method: 'POST',
            body: JSON.stringify([{
                user_id: authData.user.id,
                nome,
                email,
                telefone,
                data_nascimento
            }])
        });
        
        return res.json({
            success: true,
            message: 'Paciente cadastrado com sucesso!',
            userId: authData.user.id
        });
    } catch (error) {
        console.error('Admin novo paciente error:', error);
        return res.status(400).json({ 
            error: 'Erro ao cadastrar paciente',
            details: error.message 
        });
    }
}

async function handleEnviarDocumento(req, res) {
    console.log('Handling enviar documento');
    
    const admin = await verifyAdmin(req);
    if (!admin.valid) return res.status(403).json({ error: admin.error });
    
    let body;
    try {
        body = await parseBody(req);
    } catch (error) {
        return res.status(400).json({ error: 'Erro ao parsear body' });
    }
    
    const { paciente_id, nome, tipo, url } = body;
    
    if (!paciente_id || !nome || !url) {
        return res.status(400).json({ error: 'Preencha todos os campos obrigatórios' });
    }
    
    try {
        const [documento] = await fetchSupabase('documentos', {
            method: 'POST',
            body: JSON.stringify([{
                paciente_id,
                nome,
                tipo,
                url,
                data: new Date().toISOString().split('T')[0]
            }])
        });
        
        return res.json(documento || { id: Date.now() });
    } catch (error) {
        console.error('Enviar documento error:', error);
        return res.status(500).json({ 
            error: 'Erro ao enviar documento',
            details: error.message 
        });
    }
}

async function handleEnviarOrientacao(req, res) {
    console.log('Handling enviar orientacao');
    
    const admin = await verifyAdmin(req);
    if (!admin.valid) return res.status(403).json({ error: admin.error });
    
    let body;
    try {
        body = await parseBody(req);
    } catch (error) {
        return res.status(400).json({ error: 'Erro ao parsear body' });
    }
    
    const { paciente_id, titulo, conteudo } = body;
    
    if (!paciente_id || !titulo || !conteudo) {
        return res.status(400).json({ error: 'Preencha todos os campos obrigatórios' });
    }
    
    try {
        const [orientacao] = await fetchSupabase('orientacoes', {
            method: 'POST',
            body: JSON.stringify([{
                paciente_id,
                titulo,
                conteudo,
                lida: false
            }])
        });
        
        return res.json(orientacao || { id: Date.now() });
    } catch (error) {
        console.error('Enviar orientacao error:', error);
        return res.status(500).json({ 
            error: 'Erro ao enviar orientação',
            details: error.message 
        });
    }
}

async function handleAdicionarFoto(req, res) {
    console.log('Handling adicionar foto');
    
    const admin = await verifyAdmin(req);
    if (!admin.valid) return res.status(403).json({ error: admin.error });
    
    let body;
    try {
        body = await parseBody(req);
    } catch (error) {
        return res.status(400).json({ error: 'Erro ao parsear body' });
    }
    
    const { paciente_id, tipo, url, tratamento, data, observacoes } = body;
    
    if (!paciente_id || !url) {
        return res.status(400).json({ error: 'Preencha os campos obrigatórios' });
    }
    
    try {
        const [foto] = await fetchSupabase('fotos', {
            method: 'POST',
            body: JSON.stringify([{
                paciente_id,
                tipo,
                url,
                tratamento,
                observacoes,
                data: data || new Date().toISOString().split('T')[0]
            }])
        });
        
        return res.json(foto || { id: Date.now() });
    } catch (error) {
        console.error('Adicionar foto error:', error);
        return res.status(500).json({ 
            error: 'Erro ao adicionar foto',
            details: error.message 
        });
    }
}

async function handleNovaConsulta(req, res) {
    console.log('Handling nova consulta');
    
    const admin = await verifyAdmin(req);
    if (!admin.valid) return res.status(403).json({ error: admin.error });
    
    let body;
    try {
        body = await parseBody(req);
    } catch (error) {
        return res.status(400).json({ error: 'Erro ao parsear body' });
    }
    
    const { paciente_id, data, tipo, observacoes } = body;
    
    if (!paciente_id || !data || !tipo) {
        return res.status(400).json({ error: 'Preencha os campos obrigatórios' });
    }
    
    try {
        const [consulta] = await fetchSupabase('consultas', {
            method: 'POST',
            body: JSON.stringify([{
                paciente_id,
                data,
                tipo,
                observacoes
            }])
        });
        
        return res.json(consulta || { id: Date.now() });
    } catch (error) {
        console.error('Nova consulta error:', error);
        return res.status(500).json({ 
            error: 'Erro ao registrar consulta',
            details: error.message 
        });
    }
}

async function handleAdminConsultas(req, res) {
    console.log('Handling admin consultas');
    
    const admin = await verifyAdmin(req);
    if (!admin.valid) return res.status(403).json({ error: admin.error });
    
    try {
        const consultas = await fetchSupabase('consultas?select=*,pacientes(nome)&order=data.desc&limit=50');
        
        return res.json(consultas.map(c => ({
            ...c,
            paciente_nome: c.pacientes?.nome
        })));
    } catch (error) {
        console.error('Admin consultas error:', error);
        return res.status(500).json({ 
            error: 'Erro ao buscar consultas',
            details: error.message 
        });
    }
}

async function handleAdminOrientacoes(req, res) {
    console.log('Handling admin orientacoes');
    
    const admin = await verifyAdmin(req);
    if (!admin.valid) return res.status(403).json({ error: admin.error });
    
    try {
        const orientacoes = await fetchSupabase('orientacoes?select=*,pacientes(nome)&order=created_at.desc&limit=50');
        
        return res.json(orientacoes.map(o => ({
            ...o,
            paciente_nome: o.pacientes?.nome
        })));
    } catch (error) {
        console.error('Admin orientacoes error:', error);
        return res.status(500).json({ 
            error: 'Erro ao buscar orientações',
            details: error.message 
        });
    }
}

// Função para parsear body
async function parseBody(req) {
    return new Promise((resolve, reject) => {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', () => {
            try {
                resolve(JSON.parse(body || '{}'));
            } catch (error) {
                console.error('Parse body error:', error);
                reject(error);
            }
        });
        req.on('error', reject);
    });
}