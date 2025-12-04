// ============================================
// BACKEND - PRONTUÁRIO ELETRÔNICO
// Compatível com Node.js 20+
// ============================================

const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Configuração do Supabase
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_KEY;
const jwtSecret = process.env.JWT_SECRET || 'seu-jwt-secret-super-seguro-aqui';
const adminUser = process.env.ADMIN_USER || 'Admin';
const adminPassword = process.env.ADMIN_PASSWORD || 'Admin123';

// Cria cliente do Supabase
const supabase = createClient(supabaseUrl, supabaseServiceKey);

// ============================================
// FUNÇÕES UTILITÁRIAS
// ============================================

function setCorsHeaders(res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
}

function verifyToken(authHeader) {
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        throw new Error('Token não fornecido');
    }
    const token = authHeader.split(' ')[1];
    return jwt.verify(token, jwtSecret);
}

function verifyAdminToken(authHeader) {
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        throw new Error('Token não fornecido');
    }
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, jwtSecret);
    if (!decoded.isAdmin) {
        throw new Error('Acesso não autorizado');
    }
    return decoded;
}

// ============================================
// HANDLER PRINCIPAL
// ============================================

module.exports = async (req, res) => {
    // Configura CORS
    setCorsHeaders(res);
    
    // Handle CORS preflight
    if (req.method === 'OPTIONS') {
        res.status(200).end();
        return;
    }
    
    try {
        const url = req.url || '';
        const method = req.method || 'GET';
        
        console.log(`[${method}] ${url}`);
        
        // Coleta o corpo da requisição
        let body = '';
        for await (const chunk of req) {
            body += chunk.toString();
        }
        
        let data = {};
        if (body && body.trim() !== '') {
            try {
                data = JSON.parse(body);
            } catch (e) {
                console.log('Body não é JSON:', body.substring(0, 100));
            }
        }
        
        // ============================================
        // ROTAS DE AUTENTICAÇÃO
        // ============================================
        
        // CADASTRO DE PACIENTE
        if (url.includes('/api/auth/register') && method === 'POST') {
            console.log('Tentando cadastrar paciente:', data);
            
            const { name, cpf, dob, password } = data;
            
            // Validação básica
            if (!name || !cpf || !dob || !password) {
                return res.status(400).json({ 
                    error: 'Todos os campos são obrigatórios' 
                });
            }
            
            // Limpa CPF
            const cleanCpf = cpf.replace(/\D/g, '');
            
            // Verifica se CPF já existe
            const { data: existing, error: checkError } = await supabase
                .from('patients')
                .select('id')
                .eq('cpf', cleanCpf)
                .maybeSingle();
            
            if (checkError) {
                console.error('Erro ao verificar CPF:', checkError);
                return res.status(500).json({ error: 'Erro interno do servidor' });
            }
            
            if (existing) {
                return res.status(400).json({ error: 'CPF já cadastrado' });
            }
            
            // Hash da senha
            const passwordHash = await bcrypt.hash(password, 10);
            
            // Insere paciente
            const { data: newPatient, error: insertError } = await supabase
                .from('patients')
                .insert({
                    name: name.trim(),
                    cpf: cleanCpf,
                    dob,
                    password_hash: passwordHash
                })
                .select()
                .single();
            
            if (insertError) {
                console.error('Erro ao inserir paciente:', insertError);
                return res.status(500).json({ error: 'Erro ao cadastrar paciente' });
            }
            
            return res.status(201).json({ 
                success: true, 
                message: 'Cadastro realizado com sucesso' 
            });
        }
        
        // LOGIN DE PACIENTE
        if (url.includes('/api/auth/login') && method === 'POST') {
            console.log('Tentando login paciente');
            
            const { cpf, password } = data;
            
            if (!cpf || !password) {
                return res.status(400).json({ error: 'CPF e senha são obrigatórios' });
            }
            
            const cleanCpf = cpf.replace(/\D/g, '');
            
            const { data: patient, error } = await supabase
                .from('patients')
                .select('*')
                .eq('cpf', cleanCpf)
                .maybeSingle();
            
            if (error || !patient) {
                console.error('Paciente não encontrado:', error);
                return res.status(401).json({ error: 'CPF ou senha incorretos' });
            }
            
            // Verifica senha
            const validPassword = await bcrypt.compare(password, patient.password_hash);
            if (!validPassword) {
                return res.status(401).json({ error: 'CPF ou senha incorretos' });
            }
            
            // Gera token
            const token = jwt.sign(
                { 
                    id: patient.id, 
                    cpf: patient.cpf,
                    type: 'patient'
                },
                jwtSecret,
                { expiresIn: '7d' }
            );
            
            // Remove senha do retorno
            const { password_hash, ...user } = patient;
            
            return res.status(200).json({ 
                success: true,
                token, 
                user 
            });
        }
        
        // LOGIN DE ADMIN
        if (url.includes('/api/admin/login') && method === 'POST') {
            console.log('Tentando login admin');
            
            const { username, password } = data;
            
            if (username !== adminUser || password !== adminPassword) {
                return res.status(401).json({ error: 'Credenciais inválidas' });
            }
            
            const token = jwt.sign(
                { isAdmin: true, type: 'admin' }, 
                jwtSecret, 
                { expiresIn: '24h' }
            );
            
            return res.status(200).json({ 
                success: true,
                token 
            });
        }
        
        // ============================================
        // ROTAS DO PACIENTE (PROTEGIDAS)
        // ============================================
        
        // HISTÓRICO DO PACIENTE
        if (url.includes('/api/patient/history') && method === 'GET') {
            try {
                const decoded = verifyToken(req.headers.authorization);
                
                const { data: history, error } = await supabase
                    .from('consultations')
                    .select('*')
                    .eq('patient_id', decoded.id)
                    .order('date', { ascending: false });
                
                if (error) throw error;
                
                return res.status(200).json(history || []);
            } catch (error) {
                return res.status(401).json({ error: error.message });
            }
        }
        
        // EXAMES DO PACIENTE
        if (url.includes('/api/patient/exams') && method === 'GET') {
            try {
                const decoded = verifyToken(req.headers.authorization);
                
                const { data: exams, error } = await supabase
                    .from('exams')
                    .select('*')
                    .eq('patient_id', decoded.id)
                    .order('created_at', { ascending: false });
                
                if (error) throw error;
                
                return res.status(200).json(exams || []);
            } catch (error) {
                return res.status(401).json({ error: error.message });
            }
        }
        
        // ============================================
        // ROTAS DO ADMIN (PROTEGIDAS)
        // ============================================
        
        // LISTAR TODOS OS CLIENTES
        if (url.includes('/api/admin/clients') && method === 'GET' && !url.includes('/clients/')) {
            try {
                verifyAdminToken(req.headers.authorization);
                
                const { data: clients, error } = await supabase
                    .from('patients')
                    .select('id, name, cpf, dob, avatar_url, created_at')
                    .order('name');
                
                if (error) throw error;
                
                return res.status(200).json(clients || []);
            } catch (error) {
                return res.status(401).json({ error: error.message });
            }
        }
        
        // DETALHES DE UM CLIENTE
        if (url.match(/\/api\/admin\/clients\/[^/]+$/) && method === 'GET') {
            try {
                verifyAdminToken(req.headers.authorization);
                
                const clientId = url.split('/').pop();
                
                const { data: client, error } = await supabase
                    .from('patients')
                    .select('id, name, cpf, dob, avatar_url, created_at')
                    .eq('id', clientId)
                    .single();
                
                if (error) throw error;
                
                return res.status(200).json(client);
            } catch (error) {
                return res.status(401).json({ error: error.message });
            }
        }
        
        // HISTÓRICO DE UM CLIENTE
        if (url.match(/\/api\/admin\/clients\/[^/]+\/history$/) && method === 'GET') {
            try {
                verifyAdminToken(req.headers.authorization);
                
                const parts = url.split('/');
                const clientId = parts[parts.length - 2];
                
                const { data: history, error } = await supabase
                    .from('consultations')
                    .select('*')
                    .eq('patient_id', clientId)
                    .order('date', { ascending: false });
                
                if (error) throw error;
                
                return res.status(200).json(history || []);
            } catch (error) {
                return res.status(401).json({ error: error.message });
            }
        }
        
        // ADICIONAR CONSULTA
        if (url.match(/\/api\/admin\/clients\/[^/]+\/history$/) && method === 'POST') {
            try {
                verifyAdminToken(req.headers.authorization);
                
                const parts = url.split('/');
                const clientId = parts[parts.length - 2];
                const { date, time, type, notes } = data;
                
                if (!date || !type) {
                    return res.status(400).json({ error: 'Data e tipo são obrigatórios' });
                }
                
                const { data: consultation, error } = await supabase
                    .from('consultations')
                    .insert({
                        patient_id: clientId,
                        date,
                        time: time || '00:00',
                        type,
                        notes: notes || ''
                    })
                    .select()
                    .single();
                
                if (error) throw error;
                
                return res.status(201).json(consultation);
            } catch (error) {
                return res.status(400).json({ error: error.message });
            }
        }
        
        // EXAMES DE UM CLIENTE
        if (url.match(/\/api\/admin\/clients\/[^/]+\/exams$/) && method === 'GET') {
            try {
                verifyAdminToken(req.headers.authorization);
                
                const parts = url.split('/');
                const clientId = parts[parts.length - 2];
                
                const { data: exams, error } = await supabase
                    .from('exams')
                    .select('*')
                    .eq('patient_id', clientId)
                    .order('created_at', { ascending: false });
                
                if (error) throw error;
                
                return res.status(200).json(exams || []);
            } catch (error) {
                return res.status(401).json({ error: error.message });
            }
        }
        
        // ADICIONAR EXAME (simplificado - sem upload de arquivo por enquanto)
        if (url.match(/\/api\/admin\/clients\/[^/]+\/exams$/) && method === 'POST') {
            try {
                verifyAdminToken(req.headers.authorization);
                
                const parts = url.split('/');
                const clientId = parts[parts.length - 2];
                const { type, file_url } = data;
                
                if (!type || !file_url) {
                    return res.status(400).json({ error: 'Tipo e URL do arquivo são obrigatórios' });
                }
                
                const { data: exam, error } = await supabase
                    .from('exams')
                    .insert({
                        patient_id: clientId,
                        type,
                        file_url
                    })
                    .select()
                    .single();
                
                if (error) throw error;
                
                return res.status(201).json(exam);
            } catch (error) {
                return res.status(400).json({ error: error.message });
            }
        }
        
        // ROTA DE TESTE
        if (url === '/api/test' || url === '/api') {
            return res.status(200).json({ 
                message: 'API está funcionando',
                timestamp: new Date().toISOString(),
                environment: 'production'
            });
        }
        
        // ROTA NÃO ENCONTRADA
        console.log('Rota não encontrada:', url);
        return res.status(404).json({ 
            error: 'Rota não encontrada',
            path: url,
            method: method
        });
        
    } catch (error) {
        console.error('Erro interno do servidor:', error);
        return res.status(500).json({ 
            error: 'Erro interno do servidor',
            message: error.message
        });
    }
};