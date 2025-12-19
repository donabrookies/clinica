// ============================================
// BACKEND - PRONTUÁRIO ELETRÔNICO (VERSÃO COM MÉDICOS E AGENDAMENTOS, TALK API E LEMBRETES)
// ============================================

const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cron = require('node-cron');

// Configuração do Supabase
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_KEY;
const jwtSecret = process.env.JWT_SECRET || 'seu-jwt-secret-super-seguro-aqui';
const adminUser = process.env.ADMIN_USER || 'Admin';
const adminPassword = process.env.ADMIN_PASSWORD || 'Admin123';

// Configuração Talk API
const TALK_API_TOKEN = "xO6iMSrK0uecIJ2uh4TqJFZcuTo9th";
const TALK_API_URL = "https://talkapi.ingaja.com.br/api/messages/send";

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

// Função para fazer upload de arquivo para o Supabase Storage
async function uploadFileToStorage(bucket, path, fileBuffer, contentType) {
    try {
        console.log(`Uploading file to ${bucket}/${path}`);

        const { data, error } = await supabase
            .storage
            .from(bucket)
            .upload(path, fileBuffer, {
                contentType: contentType,
                upsert: true
            });

        if (error) {
            console.error('Upload error:', error);
            throw error;
        }

        // Obtém a URL pública
        const { data: urlData } = supabase
            .storage
            .from(bucket)
            .getPublicUrl(path);

        console.log('Upload successful, public URL:', urlData.publicUrl);
        return urlData.publicUrl;
    } catch (error) {
        console.error('Error in uploadFileToStorage:', error);
        throw error;
    }
}

// ============================================
// FUNÇÃO PARA ENVIAR MENSAGENS VIA TALK API
// ============================================

async function sendTalkMessage(phone, message) {
    try {
        // Formata o telefone: remove caracteres não numéricos e adiciona 55
        let formattedPhone = phone.replace(/\D/g, '');
        if (!formattedPhone.startsWith('55')) {
            formattedPhone = '55' + formattedPhone;
        }

        const body = {
            number: formattedPhone,
            body: message,
            userId: "",
            queueId: "",
            sendSignature: false,
            closeTicket: false
        };

        console.log('Enviando mensagem via Talk API para:', formattedPhone);
        console.log('Mensagem:', message);

        const response = await fetch(TALK_API_URL, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${TALK_API_TOKEN}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(body)
        });

        const result = await response.json();
        console.log('Resposta do Talk API:', result);

        if (!response.ok) {
            console.error('Erro ao enviar mensagem via Talk API:', result);
            return false;
        }

        return true;
    } catch (error) {
        console.error('Erro na função sendTalkMessage:', error);
        return false;
    }
}

// ============================================
// FUNÇÃO PARA ENVIAR LEMBRETES DE CONSULTAS
// ============================================

async function sendAppointmentReminders() {
    try {
        console.log('=== INICIANDO ENVIO DE LEMBRETES DE CONSULTAS ===');

        // Obter data de amanhã no formato YYYY-MM-DD
        const today = new Date();
        const tomorrow = new Date(today);
        tomorrow.setDate(today.getDate() + 1);
        const tomorrowStr = tomorrow.toISOString().split('T')[0];

        console.log(`Buscando consultas para amanhã (${tomorrowStr})...`);

        // Buscar todas as consultas agendadas para amanhã
        const { data: appointments, error } = await supabase
            .from('appointments')
            .select(`
                *,
                patients (
                    name,
                    cpf,
                    whatsapp
                ),
                doctors (
                    name,
                    specialty
                )
            `)
            .eq('appointment_date', tomorrowStr)
            .eq('status', 'agendado');

        if (error) {
            console.error('Erro ao buscar consultas:', error);
            return;
        }

        console.log(`Encontradas ${appointments?.length || 0} consultas para amanhã`);

        // Enviar lembretes para cada consulta
        if (appointments && appointments.length > 0) {
            for (const appointment of appointments) {
                try {
                    if (appointment.patients?.whatsapp) {
                        // Formatar data para exibição
                        const appointmentDate = new Date(appointment.appointment_date + 'T00:00:00');
                        const formattedDate = appointmentDate.toLocaleDateString('pt-BR', {
                            weekday: 'long',
                            year: 'numeric',
                            month: 'long',
                            day: 'numeric'
                        });

                        // Formatar hora
                        const timeParts = appointment.appointment_time.split(':');
                        const formattedTime = `${timeParts[0]}:${timeParts[1]}`;

                        // Montar mensagem de lembrete
                        const reminderMessage = `*Lembrete de Consulta* 🏥\n\nOlá ${appointment.patients.name},\n\nEste é um lembrete amigável da sua consulta marcada para *amanhã*:\n\n📅 *Data:* ${formattedDate}\n⏰ *Horário:* ${formattedTime}\n👨‍⚕️ *Médico:* ${appointment.doctors.name}\n🏥 *Especialidade:* ${appointment.doctors.specialty}\n\n📍 *Local:* Clínica Médica\n📞 *Contato:* (11) 9999-9999\n\n*Observações importantes:*\n- Chegue com 15 minutos de antecedência\n- Traga seus documentos e exames recentes\n- Em caso de desistência, cancele com antecedência\n\nAgradecemos sua confiança! 🙏`;

                        // Enviar mensagem via Talk API
                        const sent = await sendTalkMessage(appointment.patients.whatsapp, reminderMessage);

                        if (sent) {
                            console.log(`✅ Lembrete enviado para ${appointment.patients.name} (${appointment.patients.whatsapp})`);
                        } else {
                            console.log(`❌ Falha ao enviar lembrete para ${appointment.patients.name}`);
                        }

                        // Aguardar 1 segundo entre envios para evitar sobrecarga
                        await new Promise(resolve => setTimeout(resolve, 1000));
                    } else {
                        console.log(`⚠️ WhatsApp não cadastrado para ${appointment.patients?.name}`);
                    }
                } catch (error) {
                    console.error(`Erro ao processar lembrete para consulta ${appointment.id}:`, error);
                }
            }
        }

        console.log('=== ENVIO DE LEMBRETES CONCLUÍDO ===\n');

    } catch (error) {
        console.error('Erro geral no envio de lembretes:', error);
    }
}

// ============================================
// NOVA FUNÇÃO: ENVIAR LEMBRETES PARA UMA DATA ESPECÍFICA (MANUAL)
// ============================================

async function sendRemindersForDate(dateStr) {
    try {
        console.log('=== ENVIO MANUAL DE LEMBRETES ===');
        console.log(`Enviando lembretes para a data: ${dateStr}`);

        // Buscar todas as consultas agendadas para a data específica
        const { data: appointments, error } = await supabase
            .from('appointments')
            .select(`
                *,
                patients (
                    name,
                    cpf,
                    whatsapp
                ),
                doctors (
                    name,
                    specialty
                )
            `)
            .eq('appointment_date', dateStr)
            .eq('status', 'agendado');

        if (error) {
            console.error('Erro ao buscar consultas:', error);
            return { success: false, error: error.message };
        }

        console.log(`Encontradas ${appointments?.length || 0} consultas para ${dateStr}`);

        let sentCount = 0;
        let failedCount = 0;

        // Enviar lembretes para cada consulta
        if (appointments && appointments.length > 0) {
            for (const appointment of appointments) {
                try {
                    if (appointment.patients?.whatsapp) {
                        // Formatar data para exibição
                        const appointmentDate = new Date(appointment.appointment_date + 'T00:00:00');
                        const formattedDate = appointmentDate.toLocaleDateString('pt-BR', {
                            weekday: 'long',
                            year: 'numeric',
                            month: 'long',
                            day: 'numeric'
                        });

                        // Formatar hora
                        const timeParts = appointment.appointment_time.split(':');
                        const formattedTime = `${timeParts[0]}:${timeParts[1]}`;

                        // Montar mensagem de lembrete
                        const reminderMessage = `*Lembrete de Consulta* 🏥\n\nOlá ${appointment.patients.name},\n\nEste é um lembrete da sua consulta marcada para:\n\n📅 *Data:* ${formattedDate}\n⏰ *Horário:* ${formattedTime}\n👨‍⚕️ *Médico:* ${appointment.doctors.name}\n🏥 *Especialidade:* ${appointment.doctors.specialty}\n\n📍 *Local:* Clínica Médica\n📞 *Contato:* (11) 9999-9999\n\n*Observações importantes:*\n- Chegue com 15 minutos de antecedência\n- Traga seus documentos e exames recentes\n- Em caso de desistência, cancele com antecedência\n\nAgradecemos sua confiança! 🙏`;

                        // Enviar mensagem via Talk API
                        const sent = await sendTalkMessage(appointment.patients.whatsapp, reminderMessage);

                        if (sent) {
                            console.log(`✅ Lembrete enviado para ${appointment.patients.name} (${appointment.patients.whatsapp})`);
                            sentCount++;
                        } else {
                            console.log(`❌ Falha ao enviar lembrete para ${appointment.patients.name}`);
                            failedCount++;
                        }

                        // Aguardar 1 segundo entre envios para evitar sobrecarga
                        await new Promise(resolve => setTimeout(resolve, 1000));
                    } else {
                        console.log(`⚠️ WhatsApp não cadastrado para ${appointment.patients?.name}`);
                        failedCount++;
                    }
                } catch (error) {
                    console.error(`Erro ao processar lembrete para consulta ${appointment.id}:`, error);
                    failedCount++;
                }
            }
        }

        console.log('=== ENVIO MANUAL CONCLUÍDO ===');
        console.log(`Total: ${sentCount + failedCount}, Enviados: ${sentCount}, Falhas: ${failedCount}`);

        return {
            success: true,
            message: `Lembretes enviados: ${sentCount} com sucesso, ${failedCount} falhas`,
            sent: sentCount,
            failed: failedCount,
            total: appointments?.length || 0
        };

    } catch (error) {
        console.error('Erro geral no envio manual de lembretes:', error);
        return { success: false, error: error.message };
    }
}

// ============================================
// CONFIGURAR CRON JOB PARA ENVIAR LEMBRETES
// ============================================

// Configurar para executar todos os dias às 10h00 da manhã
// Formato: segundo minuto hora dia-do-mês mês dia-da-semana
cron.schedule('0 10 * * *', async () => {
    console.log('Executando job de lembretes automáticos...');
    await sendAppointmentReminders();
}, {
    scheduled: true,
    timezone: "America/Sao_Paulo" // Fuso horário de Brasília
});

// Função manual para testar o envio de lembretes
async function testReminders() {
    console.log('Testando envio de lembretes...');
    await sendAppointmentReminders();
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
                console.log('Body não é JSON, tratando como raw:', body.substring(0, 100));
            }
        }

        // ============================================
        // ROTAS PÚBLICAS
        // ============================================

        // ROTA RAIZ - Health Check
        if (url === '/' && method === 'GET') {
            return res.status(200).json({
                message: 'API do Prontuário Eletrônico',
                version: '2.0.0',
                status: 'online',
                features: ['pacientes', 'médicos', 'agendamentos', 'lembretes_automáticos'],
                timestamp: new Date().toISOString()
            });
        }

        // TESTE DE CONEXÃO COM SUPABASE
        if (url === '/api/health' && method === 'GET') {
            try {
                // Testa conexão com Supabase
                const { data, error } = await supabase
                    .from('patients')
                    .select('count')
                    .limit(1);

                return res.status(200).json({
                    status: 'healthy',
                    supabase: error ? 'connection_error' : 'connected',
                    timestamp: new Date().toISOString()
                });
            } catch (error) {
                return res.status(500).json({
                    status: 'unhealthy',
                    error: error.message,
                    timestamp: new Date().toISOString()
                });
            }
        }

        // ============================================
        // ROTAS DE AUTENTICAÇÃO
        // ============================================

        // CADASTRO DE PACIENTE
        if (url === '/api/auth/register' && method === 'POST') {
            console.log('Tentando cadastrar paciente:', data);

            const { name, cpf, dob, password, whatsapp } = data;

            // Validação básica
            if (!name || !cpf || !dob || !password || !whatsapp) {
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
                    password_hash: passwordHash,
                    whatsapp: whatsapp.trim()
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
        if (url === '/api/auth/login' && method === 'POST') {
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
        if (url === '/api/admin/login' && method === 'POST') {
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
        // NOVA ROTA: ENVIAR LEMBRETES MANUALMENTE PARA UMA DATA ESPECÍFICA
        // ============================================
        if (url === '/api/admin/send-reminders' && method === 'POST') {
            try {
                verifyAdminToken(req.headers.authorization);

                const { date } = data;

                if (!date) {
                    return res.status(400).json({ error: 'Data é obrigatória' });
                }

                console.log('Iniciando envio manual de lembretes para:', date);
                const result = await sendRemindersForDate(date);

                if (!result.success) {
                    return res.status(500).json({ error: result.error });
                }

                return res.status(200).json({
                    success: true,
                    message: result.message,
                    details: {
                        sent: result.sent,
                        failed: result.failed,
                        total: result.total
                    }
                });
            } catch (error) {
                return res.status(401).json({ error: error.message });
            }
        }

        // ============================================
        // ROTA: TESTAR LEMBRETES (APENAS PARA TESTES)
        // ============================================
        if (url === '/api/admin/test-reminders' && method === 'POST') {
            try {
                verifyAdminToken(req.headers.authorization);

                console.log('Iniciando teste de lembretes...');
                await testReminders();

                return res.status(200).json({
                    success: true,
                    message: 'Teste de lembretes iniciado. Verifique os logs.'
                });
            } catch (error) {
                return res.status(401).json({ error: error.message });
            }
        }

        // ============================================
        // ROTAS DO PACIENTE (PROTEGIDAS)
        // ============================================

        // HISTÓRICO DO PACIENTE
        if (url === '/api/patient/history' && method === 'GET') {
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
        if (url === '/api/patient/exams' && method === 'GET') {
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

        // UPLOAD DE AVATAR DO PACIENTE
        if (url === '/api/patient/avatar' && method === 'POST') {
            try {
                const decoded = verifyToken(req.headers.authorization);

                // Espera receber { avatar: base64String }
                const { avatar } = data;

                if (!avatar) {
                    return res.status(400).json({ error: 'Avatar é obrigatório' });
                }

                // Verifica se é base64 válido
                if (!avatar.startsWith('data:image/')) {
                    return res.status(400).json({ error: 'Formato de imagem inválido' });
                }

                // Extrai o tipo MIME da string base64
                const matches = avatar.match(/^data:image\/(\w+);base64,/);
                if (!matches) {
                    return res.status(400).json({ error: 'Formato base64 inválido' });
                }

                const mimeType = matches[1];
                const base64Data = avatar.replace(/^data:image\/\w+;base64,/, '');
                const buffer = Buffer.from(base64Data, 'base64');

                // Define o caminho no storage
                const fileName = `patient-${decoded.id}-${Date.now()}.${mimeType}`;
                const path = `avatars/${fileName}`;

                console.log(`Uploading avatar for patient ${decoded.id}, path: ${path}`);

                // Faz upload
                const publicUrl = await uploadFileToStorage('uploads', path, buffer, `image/${mimeType}`);

                // Atualiza o paciente com a nova URL do avatar
                const { data: updatedPatient, error: updateError } = await supabase
                    .from('patients')
                    .update({ avatar_url: publicUrl })
                    .eq('id', decoded.id)
                    .select()
                    .single();

                if (updateError) {
                    console.error('Error updating patient:', updateError);
                    throw updateError;
                }

                return res.status(200).json({
                    success: true,
                    avatar_url: publicUrl
                });
            } catch (error) {
                console.error('Error in /api/patient/avatar:', error);
                return res.status(500).json({
                    error: 'Erro ao processar imagem: ' + error.message
                });
            }
        }

        // ============================================
        // ROTAS DE MÉDICOS E AGENDAMENTOS (PACIENTE)
        // ============================================

        // LISTAR MÉDICOS DISPONÍVEIS
        if (url === '/api/doctors' && method === 'GET') {
            try {
                const decoded = verifyToken(req.headers.authorization);

                const { data: doctors, error } = await supabase
                    .from('doctors')
                    .select('*')
                    .order('name');

                if (error) throw error;

                return res.status(200).json(doctors || []);
            } catch (error) {
                return res.status(401).json({ error: error.message });
            }
        }

        // LISTAR AGENDAMENTOS DO PACIENTE
        if (url === '/api/patient/appointments' && method === 'GET') {
            try {
                const decoded = verifyToken(req.headers.authorization);

                const { data: appointments, error } = await supabase
                    .from('appointments')
                    .select(`
                        *,
                        doctors (
                            name,
                            specialty
                        )
                    `)
                    .eq('patient_id', decoded.id)
                    .order('appointment_date', { ascending: true })
                    .order('appointment_time', { ascending: true });

                if (error) throw error;

                return res.status(200).json(appointments || []);
            } catch (error) {
                return res.status(401).json({ error: error.message });
            }
        }

        // LISTAR DIAS DE TRABALHO DO MÉDICO
        if (url.startsWith('/api/doctor-work-days') && method === 'GET') {
            try {
                const decoded = verifyToken(req.headers.authorization);
                const queryString = url.split('?')[1] || '';
                const params = new URLSearchParams(queryString);
                const doctor_id = params.get('doctor_id');

                if (!doctor_id) {
                    return res.status(400).json({ error: 'ID do médico é obrigatório' });
                }

                const { data: workDays, error } = await supabase
                    .from('doctor_work_days')
                    .select('*')
                    .eq('doctor_id', doctor_id)
                    .gte('work_date', new Date().toISOString().split('T')[0])
                    .order('work_date');

                if (error) throw error;

                return res.status(200).json(workDays || []);
            } catch (error) {
                return res.status(401).json({ error: error.message });
            }
        }

        // ============================================
        // ROTAS DE AGENDAMENTOS - ORDEM É CRÍTICA
        // ============================================

        // 1. CANCELAR AGENDAMENTO - DEVE VIR ANTES DA CRIAÇÃO
        if (url.includes('/api/appointments/') && url.includes('/cancel') && method === 'POST') {
            try {
                const decoded = verifyToken(req.headers.authorization);

                // Extrair ID da URL: /api/appointments/{id}/cancel
                const parts = url.split('/');
                const appointmentId = parts[3];

                console.log('Cancelando agendamento ID:', appointmentId);

                // Verificar se o agendamento existe e pertence ao paciente
                const { data: appointment, error: fetchError } = await supabase
                    .from('appointments')
                    .select('*')
                    .eq('id', appointmentId)
                    .eq('patient_id', decoded.id)
                    .single();

                if (fetchError || !appointment) {
                    return res.status(404).json({ error: 'Agendamento não encontrado' });
                }

                // Atualizar status para cancelado
                const { error } = await supabase
                    .from('appointments')
                    .update({ status: 'cancelado' })
                    .eq('id', appointmentId);

                if (error) {
                    console.error('Erro ao atualizar agendamento:', error);
                    throw error;
                }

                return res.status(200).json({ success: true });
            } catch (error) {
                console.error('Erro ao cancelar agendamento:', error);
                return res.status(500).json({ error: 'Erro ao cancelar agendamento' });
            }
        }

        // 2. CRIAR AGENDAMENTO (COM ENVIO DE MENSAGEM VIA TALK API)
        if (url === '/api/appointments' && method === 'POST') {
            try {
                const decoded = verifyToken(req.headers.authorization);

                const { doctor_id, appointment_date, notes, whatsapp } = data;

                if (!doctor_id || !appointment_date || !whatsapp) {
                    return res.status(400).json({ error: 'Médico, data e WhatsApp são obrigatórios' });
                }

                // Horário fixo
                const appointment_time = '08:00';

                // Verificar se o médico trabalha nesse dia
                const { data: workDay, error: workDayError } = await supabase
                    .from('doctor_work_days')
                    .select('*')
                    .eq('doctor_id', doctor_id)
                    .eq('work_date', appointment_date)
                    .single();

                if (workDayError || !workDay) {
                    return res.status(400).json({ error: 'Médico não trabalha neste dia' });
                }

                // Verificar se já existe agendamento no mesmo horário para o mesmo médico
                const { data: existingAppointment, error: checkError } = await supabase
                    .from('appointments')   
                    .select('id')
                    .eq('doctor_id', doctor_id)
                    .eq('appointment_date', appointment_date)
                    .eq('appointment_time', appointment_time)
                    .eq('status', 'agendado')
                    .maybeSingle();

                if (existingAppointment) {
                    return res.status(400).json({ error: 'Já existe um agendamento para este horário' });
                }

                // Cria o agendamento
                const { data: appointment, error: insertError } = await supabase
                    .from('appointments')
                    .insert({
                        patient_id: decoded.id,
                        doctor_id,
                        appointment_date,
                        appointment_time,
                        notes: notes || '',
                        whatsapp: whatsapp.trim(),
                        status: 'agendado'
                    })
                    .select()
                    .single();

                if (insertError) {
                    console.error('Erro ao inserir agendamento:', insertError);
                    throw insertError;
                }

                // ============================================
                // ENVIO DE MENSAGEM VIA TALK API
                // ============================================
                try {
                    // Buscar dados do paciente
                    const { data: patientData, error: patientError } = await supabase
                        .from('patients')
                        .select('name, cpf')
                        .eq('id', decoded.id)
                        .single();

                    if (!patientError && patientData) {
                        // Buscar dados do médico
                        const { data: doctorData, error: doctorError } = await supabase
                            .from('doctors')
                            .select('name')
                            .eq('id', doctor_id)
                            .single();

                        // Formatar data para mensagem
                        const dataObj = new Date(appointment_date + 'T00:00:00');
                        const dataFormatada = dataObj.toLocaleDateString('pt-BR');

                        // Montar mensagem
                        const cpfFormatado = patientData.cpf.replace(/(\d{3})(\d{3})(\d{3})(\d{2})/, '$1.$2.$3-$4');
                        const mensagem = `Olá ${patientData.name} (CPF: ${cpfFormatado}),\n\nEstamos entrando em contato para confirmar sua consulta com ${doctorData?.name || 'o médico'} no dia ${dataFormatada} às ${appointment_time}.\n\n*IMPORTANTE:* Você receberá um lembrete no dia anterior à consulta.\n\nPor favor, confirme se poderá comparecer respondendo esta mensagem.\n\nAtenciosamente,\nClínica`;

                        // Enviar mensagem via Talk API (assincrono - não bloqueia a resposta)
                        sendTalkMessage(whatsapp, mensagem)
                            .then(success => {
                                if (success) {
                                    console.log('Mensagem de confirmação enviada com sucesso para:', whatsapp);
                                } else {
                                    console.log('Falha ao enviar mensagem para:', whatsapp);
                                }
                            })
                            .catch(err => {
                                console.error('Erro ao tentar enviar mensagem:', err);
                            });
                    }
                } catch (talkError) {
                    console.error('Erro no processo de envio de mensagem:', talkError);
                    // Não falha o agendamento se a mensagem não for enviada
                }

                return res.status(201).json(appointment);
            } catch (error) {
                console.error('Erro ao criar agendamento:', error);
                return res.status(400).json({ error: error.message || 'Erro ao criar agendamento' });
            }
        }

        // ============================================
        // ROTAS DO ADMIN (PROTEGIDAS)
        // ============================================

        // LISTAR TODOS OS CLIENTES
        if (url === '/api/admin/clients' && method === 'GET') {
            try {
                verifyAdminToken(req.headers.authorization);

                const { data: clients, error } = await supabase
                    .from('patients')
                    .select('id, name, cpf, dob, avatar_url, whatsapp, created_at')
                    .order('name');

                if (error) throw error;

                return res.status(200).json(clients || []);
            } catch (error) {
                return res.status(401).json({ error: error.message });
            }
        }

        // DETALHES DE UM CLIENTE
        if (url.includes('/api/admin/clients/') && !url.includes('/history') && !url.includes('/exams') && !url.includes('/avatar') && method === 'GET') {
            try {
                verifyAdminToken(req.headers.authorization);

                const parts = url.split('/');
                const clientId = parts[parts.length - 1];

                const { data: client, error } = await supabase
                    .from('patients')
                    .select('id, name, cpf, dob, avatar_url, whatsapp, created_at')
                    .eq('id', clientId)
                    .single();

                if (error) throw error;

                return res.status(200).json(client);
            } catch (error) {
                return res.status(401).json({ error: error.message });
            }
        }

        // HISTÓRICO DE UM CLIENTE
        if (url.includes('/api/admin/clients/') && url.includes('/history') && method === 'GET') {
            try {
                verifyAdminToken(req.headers.authorization);

                const parts = url.split('/');
                const clientId = parts[4]; // /api/admin/clients/{id}/history

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
        if (url.includes('/api/admin/clients/') && url.includes('/history') && method === 'POST') {
            try {
                verifyAdminToken(req.headers.authorization);

                const parts = url.split('/');
                const clientId = parts[4];
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
        if (url.includes('/api/admin/clients/') && url.includes('/exams') && method === 'GET') {
            try {
                verifyAdminToken(req.headers.authorization);

                const parts = url.split('/');
                const clientId = parts[4];

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

        // ADICIONAR EXAME
        if (url.includes('/api/admin/clients/') && url.includes('/exams') && method === 'POST') {
            try {
                verifyAdminToken(req.headers.authorization);

                const parts = url.split('/');
                const clientId = parts[4];
                const { type, file } = data;

                if (!type || !file) {
                    return res.status(400).json({ error: 'Tipo e arquivo são obrigatórios' });
                }

                // Verifica se é base64 válido
                if (!file.startsWith('data:application/pdf;base64,')) {
                    return res.status(400).json({ error: 'Formato de arquivo inválido. Apenas PDF são aceitos.' });
                }

                // Converte base64 para buffer
                const base64Data = file.replace(/^data:application\/pdf;base64,/, '');
                const buffer = Buffer.from(base64Data, 'base64');

                // Define o caminho no storage
                const fileName = `${type.replace(/\s+/g, '-').toLowerCase()}-${clientId}-${Date.now()}.pdf`;
                const path = `exams/${fileName}`;

                console.log(`Uploading exam for client ${clientId}, path: ${path}`);

                // Faz upload
                const publicUrl = await uploadFileToStorage('uploads', path, buffer, 'application/pdf');

                // Insere o exame no banco
                const { data: exam, error: insertError } = await supabase
                    .from('exams')
                    .insert({
                        patient_id: clientId,
                        type,
                        file_url: publicUrl
                    })
                    .select()
                    .single();

                if (insertError) throw insertError;

                return res.status(201).json(exam);
            } catch (error) {
                console.error('Error uploading exam:', error);
                return res.status(500).json({ error: 'Erro ao enviar exame: ' + error.message });
            }
        }

        // UPLOAD DE AVATAR DO CLIENTE PELO ADMIN
        if (url.includes('/api/admin/clients/') && url.includes('/avatar') && method === 'POST') {
            try {
                verifyAdminToken(req.headers.authorization);

                const parts = url.split('/');
                const clientId = parts[4];
                const { avatar } = data;

                if (!avatar) {
                    return res.status(400).json({ error: 'Avatar é obrigatório' });
                }

                // Verifica se é base64 válido
                if (!avatar.startsWith('data:image/')) {
                    return res.status(400).json({ error: 'Formato de imagem inválido' });
                }

                // Extrai o tipo MIME da string base64
                const matches = avatar.match(/^data:image\/(\w+);base64,/);
                if (!matches) {
                    return res.status(400).json({ error: 'Formato base64 inválido' });
                }

                const mimeType = matches[1];
                const base64Data = avatar.replace(/^data:image\/\w+;base64,/, '');
                const buffer = Buffer.from(base64Data, 'base64');

                // Define o caminho no storage
                const fileName = `patient-${clientId}-${Date.now()}.${mimeType}`;
                const path = `avatars/${fileName}`;

                console.log(`Uploading avatar for client ${clientId}, path: ${path}`);

                // Faz upload
                const publicUrl = await uploadFileToStorage('uploads', path, buffer, `image/${mimeType}`);

                // Atualiza o paciente com a nova URL do avatar
                const { data: updatedPatient, error: updateError } = await supabase
                    .from('patients')
                    .update({ avatar_url: publicUrl })
                    .eq('id', clientId)
                    .select()
                    .single();

                if (updateError) {
                    console.error('Error updating patient:', updateError);
                    throw updateError;
                }

                return res.status(200).json({
                    success: true,
                    avatar_url: publicUrl
                });
            } catch (error) {
                console.error('Error in /api/admin/clients/avatar:', error);
                return res.status(500).json({
                    error: 'Erro ao processar imagem: ' + error.message
                });
            }
        }

        // ============================================
        // ROTAS DE MÉDICOS (ADMIN)
        // ============================================

        // LISTAR TODOS OS MÉDICOS
        if (url === '/api/admin/doctors' && method === 'GET') {
            try {
                verifyAdminToken(req.headers.authorization);

                const { data: doctors, error } = await supabase
                    .from('doctors')
                    .select('*')
                    .order('name');

                if (error) throw error;

                return res.status(200).json(doctors || []);
            } catch (error) {
                return res.status(401).json({ error: error.message });
            }
        }

        // CRIAR MÉDICO
        if (url === '/api/admin/doctors' && method === 'POST') {
            try {
                verifyAdminToken(req.headers.authorization);

                const { name, specialty, description, phone, email, avatar } = data;

                if (!name || !specialty) {
                    return res.status(400).json({ error: 'Nome e especialidade são obrigatórios' });
                }

                let avatar_url = null;
                if (avatar) {
                    // Verifica se é base64 válido
                    if (!avatar.startsWith('data:image/')) {
                        return res.status(400).json({ error: 'Formato de imagem inválido' });
                    }

                    const matches = avatar.match(/^data:image\/(\w+);base64,/);
                    if (!matches) {
                        return res.status(400).json({ error: 'Formato base64 inválido' });
                    }

                    const mimeType = matches[1];
                    const base64Data = avatar.replace(/^data:image\/\w+;base64,/, '');
                    const buffer = Buffer.from(base64Data, 'base64');

                    const fileName = `doctor-${Date.now()}.${mimeType}`;
                    const path = `doctors/${fileName}`;

                    avatar_url = await uploadFileToStorage('uploads', path, buffer, `image/${mimeType}`);
                }

                const { data: doctor, error } = await supabase
                    .from('doctors')
                    .insert({
                        name,
                        specialty,
                        description: description || '',
                        phone: phone || '',
                        email: email || '',
                        avatar_url,
                        active: true
                    })
                    .select()
                    .single();

                if (error) throw error;

                return res.status(201).json(doctor);
            } catch (error) {
                return res.status(400).json({ error: error.message });
            }
        }

        // ATUALIZAR MÉDICO
        if (url.includes('/api/admin/doctors/') && !url.includes('/work-days') && method === 'PUT') {
            try {
                verifyAdminToken(req.headers.authorization);

                const parts = url.split('/');
                const doctorId = parts[parts.length - 1];
                const { name, specialty, description, phone, email, active, avatar } = data;

                let updateData = {
                    name,
                    specialty,
                    description,
                    phone,
                    email,
                    active
                };

                if (avatar) {
                    // Verifica se é base64 válido
                    if (!avatar.startsWith('data:image/')) {
                        return res.status(400).json({ error: 'Formato de imagem inválido' });
                    }

                    const matches = avatar.match(/^data:image\/(\w+);base64,/);
                    if (!matches) {
                        return res.status(400).json({ error: 'Formato base64 inválido' });
                    }

                    const mimeType = matches[1];
                    const base64Data = avatar.replace(/^data:image\/\w+;base64,/, '');
                    const buffer = Buffer.from(base64Data, 'base64');

                    const fileName = `doctor-${doctorId}-${Date.now()}.${mimeType}`;
                    const path = `doctors/${fileName}`;

                    const avatar_url = await uploadFileToStorage('uploads', path, buffer, `image/${mimeType}`);
                    updateData.avatar_url = avatar_url;
                }

                const { data: doctor, error } = await supabase
                    .from('doctors')
                    .update(updateData)
                    .eq('id', doctorId)
                    .select()
                    .single();

                if (error) throw error;

                return res.status(200).json(doctor);
            } catch (error) {
                return res.status(400).json({ error: error.message });
            }
        }

        // DELETAR MÉDICO
        if (url.includes('/api/admin/doctors/') && !url.includes('/work-days') && method === 'DELETE') {
            try {
                verifyAdminToken(req.headers.authorization);

                const parts = url.split('/');
                const doctorId = parts[parts.length - 1];

                const { error } = await supabase
                    .from('doctors')
                    .delete()
                    .eq('id', doctorId);

                if (error) throw error;

                return res.status(200).json({ success: true });
            } catch (error) {
                return res.status(400).json({ error: error.message });
            }
        }

        // ============================================
        // ROTAS DE DIAS DE TRABALHO (ADMIN)
        // ============================================

        // LISTAR DIAS DE TRABALHO
        if (url === '/api/admin/work-days' && method === 'GET') {
            try {
                verifyAdminToken(req.headers.authorization);

                const { data: workDays, error } = await supabase
                    .from('doctor_work_days')
                    .select(`
                        *,
                        doctors (
                            name,
                            specialty
                        )
                    `)
                    .order('work_date', { ascending: false });

                if (error) throw error;

                return res.status(200).json(workDays || []);
            } catch (error) {
                return res.status(401).json({ error: error.message });
            }
        }

        // ADICIONAR DIA DE TRABALHO
        if (url === '/api/admin/doctor-work-days' && method === 'POST') {
            try {
                verifyAdminToken(req.headers.authorization);

                const { doctor_id, work_date, start_time, end_time } = data;

                if (!doctor_id || !work_date || !start_time || !end_time) {
                    return res.status(400).json({ error: 'Todos os campos são obrigatórios' });
                }

                // Verifica se já existe dia de trabalho para este médico na mesma data
                const { data: existing, error: checkError } = await supabase
                    .from('doctor_work_days')
                    .select('id')
                    .eq('doctor_id', doctor_id)
                    .eq('work_date', work_date)
                    .maybeSingle();

                if (existing) {
                    return res.status(400).json({ error: 'Já existe um dia de trabalho para esta data' });
                }

                const { data: workDay, error } = await supabase
                    .from('doctor_work_days')
                    .insert({
                        doctor_id,
                        work_date,
                        start_time,
                        end_time
                    })
                    .select()
                    .single();

                if (error) throw error;

                return res.status(201).json(workDay);
            } catch (error) {
                return res.status(400).json({ error: error.message });
            }
        }

        // DELETAR DIA DE TRABALHO
        if (url.includes('/api/admin/doctor-work-days/') && method === 'DELETE') {
            try {
                verifyAdminToken(req.headers.authorization);

                const parts = url.split('/');
                const workDayId = parts[parts.length - 1];

                const { error } = await supabase
                    .from('doctor_work_days')
                    .delete()
                    .eq('id', workDayId);

                if (error) throw error;

                return res.status(200).json({ success: true });
            } catch (error) {
                return res.status(401).json({ error: error.message });
            }
        }

        // ============================================
        // ROTAS DE AGENDAMENTOS (ADMIN) - CORRIGIDAS
        // ============================================

        // LISTAR TODOS OS AGENDAMENTOS COM FILTROS - ROTA PRINCIPAL CORRIGIDA
        if (url.startsWith('/api/admin/appointments') && !url.includes('/status') && method === 'GET') {
            try {
                verifyAdminToken(req.headers.authorization);

                // Extrair parâmetros de query da URL
                const queryString = url.split('?')[1] || '';
                const params = new URLSearchParams(queryString);
                const status = params.get('status');
                const date = params.get('date');
                const doctor_id = params.get('doctor_id');
                const search = params.get('search');

                console.log('Filtros recebidos:', { status, date, doctor_id, search });

                let query = supabase
                    .from('appointments')
                    .select(`
                        *,
                        patients (
                            name,
                            cpf,
                            whatsapp
                        ),
                        doctors (
                            name,
                            specialty
                        )
                    `);

                if (status && status.trim() !== '') {
                    query = query.eq('status', status);
                }

                if (date && date.trim() !== '') {
                    query = query.eq('appointment_date', date);
                }

                if (doctor_id && doctor_id.trim() !== '') {
                    query = query.eq('doctor_id', doctor_id);
                }

                if (search && search.trim() !== '') {
                    // Primeiro, buscar pacientes que correspondem à busca
                    const { data: matchingPatients, error: patientsError } = await supabase
                        .from('patients')
                        .select('id')
                        .or(`name.ilike.%${search}%,cpf.ilike.%${search}%`);

                    if (!patientsError && matchingPatients && matchingPatients.length > 0) {
                        const patientIds = matchingPatients.map(p => p.id);
                        query = query.in('patient_id', patientIds);
                    } else {
                        // Se não encontrar pacientes, retorna array vazio
                        return res.status(200).json([]);
                    }
                }

                query = query.order('appointment_date', { ascending: false })
                    .order('appointment_time');

                const { data: appointments, error } = await query;

                if (error) throw error;

                return res.status(200).json(appointments || []);
            } catch (error) {
                console.error('Erro ao buscar agendamentos:', error);
                return res.status(401).json({ error: error.message });
            }
        }

        // ATUALIZAR STATUS DO AGENDAMENTO - ROTA ESPECÍFICA
        if (url.includes('/api/admin/appointments/') && url.includes('/status') && method === 'PUT') {
            try {
                verifyAdminToken(req.headers.authorization);

                // Extrair ID corretamente: /api/admin/appointments/{id}/status
                const parts = url.split('/');
                const appointmentId = parts[4];

                console.log('Atualizando status do agendamento ID:', appointmentId);

                const { status } = data;

                if (!status) {
                    return res.status(400).json({ error: 'Status é obrigatório' });
                }

                if (!['agendado', 'cancelado', 'realizado'].includes(status)) {
                    return res.status(400).json({ error: 'Status inválido' });
                }

                const { data: appointment, error } = await supabase
                    .from('appointments')
                    .update({ status })
                    .eq('id', appointmentId)
                    .select()
                    .single();

                if (error) throw error;

                return res.status(200).json(appointment);
            } catch (error) {
                console.error('Erro ao atualizar status:', error);
                return res.status(400).json({ error: error.message });
            }
        }

        // ============================================
        // ROTAS DE EXCLUSÃO (ADMIN)
        // ============================================

        // DELETAR CONSULTA
        if (url.includes('/api/admin/history/') && method === 'DELETE') {
            try {
                verifyAdminToken(req.headers.authorization);

                const parts = url.split('/');
                const historyId = parts[parts.length - 1];

                const { error } = await supabase
                    .from('consultations')
                    .delete()
                    .eq('id', historyId);

                if (error) throw error;

                return res.status(200).json({ success: true });
            } catch (error) {
                return res.status(400).json({ error: error.message });
            }
        }

        // DELETAR EXAME
        if (url.includes('/api/admin/exams/') && method === 'DELETE') {
            try {
                verifyAdminToken(req.headers.authorization);

                const parts = url.split('/');
                const examId = parts[parts.length - 1];

                const { error } = await supabase
                    .from('exams')
                    .delete()
                    .eq('id', examId);

                if (error) throw error;

                return res.status(200).json({ success: true });
            } catch (error) {
                return res.status(400).json({ error: error.message });
            }
        }

        // DELETAR CLIENTE
        if (url.includes('/api/admin/clients/') && !url.includes('/history') && !url.includes('/exams') && !url.includes('/avatar') && method === 'DELETE') {
            try {
                verifyAdminToken(req.headers.authorization);

                const parts = url.split('/');
                const clientId = parts[parts.length - 1];

                const { error } = await supabase
                    .from('patients')
                    .delete()
                    .eq('id', clientId);

                if (error) throw error;

                return res.status(200).json({ success: true });
            } catch (error) {
                return res.status(401).json({ error: error.message });
            }
        }

        // ROTA DE TESTE
        if (url === '/api/test' || url === '/api') {
            return res.status(200).json({
                message: 'API está funcionando',
                timestamp: new Date().toISOString(),
                environment: 'production',
                features: ['lembretes_automáticos', 'lembretes_manuais']
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