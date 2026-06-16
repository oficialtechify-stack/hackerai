import express from "express";
import path from "path";
import dotenv from "dotenv";
import { GoogleGenAI } from "@google/genai";
import { createServer as createViteServer } from "vite";

dotenv.config();

// Ensure the Gemini API key is available
const apiKey = process.env.GEMINI_API_KEY;
let ai: GoogleGenAI | null = null;
if (apiKey) {
  ai = new GoogleGenAI({
    apiKey: apiKey,
    httpOptions: {
      headers: {
        "User-Agent": "aistudio-build",
      },
    },
  });
} else {
  console.warn("Warning: GEMINI_API_KEY environment variable is not defined.");
}

// Resilient helper to handle temporary model unavailability and spikes in demand
async function generateContentWithFallback(params: {
  contents: any;
  config?: any;
}) {
  if (!ai) {
    throw new Error("GoogleGenAI client is not initialized.");
  }

  // List of fallback models to ensure continuous security analysis even during usage spikes
  const modelsToTry = [
    "gemini-3.5-flash",
    "gemini-3.1-flash-lite",
    "gemini-flash-latest",
    "gemini-3.1-pro-preview"
  ];
  let lastError: any = null;

  for (const model of modelsToTry) {
    // Retry up to 2 times per model with a brief delay
    for (let attempt = 1; attempt <= 2; attempt++) {
      try {
        console.log(`[HackerAI] Requesting model: ${model} | Attempt: ${attempt}`);
        const response = await ai.models.generateContent({
          model,
          contents: params.contents,
          config: params.config,
        });
        return response;
      } catch (err: any) {
        lastError = err;
        console.warn(`[HackerAI] Model ${model} failed on attempt ${attempt}. Error:`, err.message || err);
        if (attempt < 2) {
          // Wait 1000ms before retrying the same model
          await new Promise((resolve) => setTimeout(resolve, 1000));
        }
      }
    }
  }

  // If both models and all attempts fail, raise the last encountered error
  throw lastError || new Error("All attempts to connect to Gemini API models failed.");
}

function isQuotaError(err: any): boolean {
  if (!err) return false;
  const errStr = typeof err === "object" ? JSON.stringify(err) : String(err);
  const msg = errStr.toLowerCase();
  return (
    msg.includes("quota") || 
    msg.includes("exhausted") || 
    msg.includes("429") || 
    msg.includes("rate_limit") ||
    msg.includes("resource_exhausted")
  );
}

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json({ limit: "10mb" }));

  // API Route: Security Code & Vulnerability audit endpoint
  app.post("/api/audit", async (req, res) => {
    let clientLanguage = "en";
    try {
      const { code, filename, language, mode } = req.body;
      if (!code || !code.trim()) {
        res.status(400).json({ error: "Code content is empty" });
        return;
      }

      clientLanguage = language || "en"; // "en" or "pt"
      
      const systemInstruction = clientLanguage === "pt"
        ? "Você é o HackerAI, uma inteligência artificial especialista em segurança ofensiva e análise estática de código. Analise o código fornecido em busca de vulnerabilidades (OWASP Top 10, Common Weakness Enumeration - CWE, buffer overflows, injeções, vulnerabilidades de lógica, segredos expostos, etc). Retorne a resposta estritamente formatada em JSON com a estrutura especificada."
        : "You are HackerAI, an AI expert in offensive security and static code analysis. Analyze the provided code for security vulnerabilities (such as OWASP Top 10, CWEs, buffer overflows, injection flaws, business logic issues, exposed credentials, etc.). Return the response strictly formatted in JSON according to the specified structure.";

      const prompt = clientLanguage === "pt"
        ? `Analise o seguinte trecho de código fornecido (Arquivo: ${filename || "não especificado"}).
Defina o nível de risco de "low" (baixo), "medium" (médio), "critical" (crítico).
Sua resposta DEVE ser estritamente em formato JSON válido, respeitando exatamente a estrutura a seguir, sem tags markdown do tipo \`\`\`json ou qualquer texto adicional fora do JSON.

Estrutura JSON esperada:
{
  "score": 65, // Nota de segurança de 0 a 100 (onde 100 é totalmente seguro)
  "summary": "Resumo executivo em português da análise",
  "vulnerabilities": [
    {
      "id": "v1",
      "title": "Título legível da vulnerabilidade",
      "severity": "critical" | "medium" | "low",
      "cwe": "CWE-89",
      "description": "Descrição detalhada descrevendo por que isso é vulnerável",
      "impact": "O impacto real de um ataque",
      "lineStart": 14, // Número aproximado da linha inicial
      "lineEnd": 20, // Linha final aproximada
      "remediation": "Como corrigir este problema específico",
      "fixedCode": "Código corrigido e seguro correspondente ao trecho problemático"
    }
  ],
  "generalRemediations": [
    "Suxestão de melhoria 1 de arquitetura",
    "Sugestão de melhoria 2"
  ]
}

Aqui está o código a ser analisado:
\`\`\`
${code}
\`\`\``
        : `Analyze the following code snippet (File: ${filename || "unspecified"}).
Determine key vulnerabilities with risk levels of "low", "medium", or "critical".
Your response MUST be strictly valid JSON conformant to the structure below, without markdown \`\`\`json wrappers or any enclosing pre-amble or post-amble text outside the JSON.

Expected JSON Structure:
{
  "score": 65, // Security score from 0 to 100 (where 100 is secure)
  "summary": "Executive summary in English",
  "vulnerabilities": [
    {
      "id": "v1",
      "title": "Readable vulnerability title",
      "severity": "critical" | "medium" | "low",
      "cwe": "CWE-89",
      "description": "Detailed description explaining why this is vulnerable",
      "impact": "Real impact should an attacker exploit this",
      "lineStart": 14,
      "lineEnd": 20,
      "remediation": "How to resolve this specific risk",
      "fixedCode": "Corrected secure code replacement"
    }
  ],
  "generalRemediations": [
    "General architectural recommendation 1",
    "General architectural recommendation 2"
  ]
}

Here is the code to analyze:
\`\`\`
${code}
\`\`\``;

      if (!ai) {
        // Mock fallback/simulation if API key is not supplied, providing structured analysis of basic items
        const isPt = clientLanguage === "pt";
        res.json({
          score: 45,
          summary: isPt 
            ? "[SIMULAÇÃO - Sem Chave de API Configurada] O analisador detectou potenciais vulnerabilidades na sua estrutura de entrada. Configure a chave do Gemini em Secrets para usufruir da inteligência em tempo real." 
            : "[SIMULATION - No API Key Configured] The analyzer detected standard potential hotspots. Configure your Gemini key in Secrets to experience real-time AI security audits.",
          vulnerabilities: [
            {
              "id": "sim-1",
              "title": isPt ? "Potencial Injeção de Comando / SQL ou Falha de Validação" : "Potential Command/SQL Injection or Context Escape",
              "severity": "critical",
              "cwe": "CWE-89 / CWE-78",
              "description": isPt 
                ? "Funções de concatenação dinâmica de strings sem validação adequada ou uso de placeholders de segurança abrem precedentes graves." 
                : "Dynamic string concatenation without proper sanitation or security parameters poses a high risk of query or control escape.",
              "impact": isPt ? "Acesso e manipulação não autorizada de dados ou execução remota de instrução." : "Unauthorized data access or remote control invocation.",
              "lineStart": 1,
              "lineEnd": 10,
              "remediation": isPt ? "Utilize parâmetros preparados, ORMs ou bibliotecas que limpem os metacaracteres." : "Use parametrized bindings, secure validation layers, or modern libraries.",
              "fixedCode": "// Secure parameterized alternative\n" + code
            },
            {
              "id": "sim-2",
              "title": isPt ? "Ausência de Tratamento Seguro de Erros" : "Generic Error / Information Leakage Risk",
              "severity": "low",
              "cwe": "CWE-209",
              "description": isPt 
                ? "A persistência em retornar detalhes brutos do sistema operacional ou banco de dados gera vazamento de segredos." 
                : "Exposing raw execution details or system stacktraces leaks infrastructure state to attackers.",
              "impact": isPt ? "Reconhecimento facilitado do ecossistema tecnológico." : "Reconnaissance helpers assisting further attack campaigns.",
              "lineStart": 1,
              "lineEnd": 15,
              "remediation": isPt ? "Capture erros globalmente e exiba apenas mensagens genéricas ao usuário final." : "Catch errors gracefully and log deep stack traces internally only.",
              "fixedCode": "try {\n  // Code block\n} catch (e) {\n  console.error(e);\n  return 'An internal error occurred. Please try again later.';\n}"
            }
          ],
          generalRemediations: isPt 
            ? ["Crie um processo robusto de revisão de código estático (SAST).", "Adote criptografia forte para comunicações sensíveis."] 
            : ["Integrate permanent static application security testing (SAST).", "Enforce strict encryption standards (TLS 1.3)."]
        });
        return;
      }

      const response = await generateContentWithFallback({
        contents: prompt,
        config: {
          systemInstruction,
          responseMimeType: "application/json",
          temperature: 0.2
        }
      });

      const responseText = response.text || "{}";
      const cleaned = responseText.replace(/```json/g, "").replace(/```/g, "").trim();
      
      try {
        const auditData = JSON.parse(cleaned);
        res.json(auditData);
      } catch (parseError) {
        console.error("Failed to parse Gemini output as JSON:", parseError, "Raw output was:", responseText);
        res.status(500).json({ error: "Invalid response format generated by Gemini", raw: responseText });
      }

    } catch (e: any) {
      console.error(e);
      if (isQuotaError(e)) {
        const isPt = clientLanguage === "pt";
        res.json({
          score: 80,
          summary: isPt 
            ? "⚠️ [Aviso de Limite de Cota do Gemini] O limite da cota gratuita diária da plataforma foi atingido. Para continuar usando a inteligência ativa sem interrupções, por favor configure sua própria chave de API em 'Settings' (Configurações) > 'Secrets' com o nome GEMINI_API_KEY no painel do Google AI Studio."
            : "⚠️ [Gemini Quota Limit Notice] The shared free-tier api quota has been fully exhausted. To bypass this and continue analyzing, define your own personalized GEMINI_API_KEY in Settings > Secrets.",
          vulnerabilities: [
            {
              "id": "quota-1",
              "title": isPt ? "Cota de API Esmagada (Resource Exhausted)" : "API Quota Limits Reached",
              "severity": "medium",
              "cwe": "CWE-400",
              "description": isPt 
                ? "O limite de requisições por minuto ou diário do modelo Gemini na cota pública foi alcançado." 
                : "The shared Google AI Studio daily API allotment for the free model tier has run out.",
              "impact": isPt ? "Incapaz de gerar análises inéditas dinâmicas de IA neste momento." : "Unable to generate live dynamic audits temporarily.",
              "lineStart": 1,
              "lineEnd": 10,
              "remediation": isPt 
                ? "Vá até o topo esquerdo/painel, clique no menu de configurações/segredos (Settings > Secrets) e insira sua chave 'GEMINI_API_KEY' pessoal." 
                : "Obtain a free or paid API key at ai.google.dev and save it under GEMINI_API_KEY inside project Secrets.",
              "fixedCode": isPt ? "// Insira sua própria GEMINI_API_KEY nos Secrets" : "// Supply your own GEMINI_API_KEY in Secrets list"
            }
          ],
          generalRemediations: isPt 
            ? ["Adicione uma GEMINI_API_KEY própria nas configurações do projeto para restabelecer auditoria dinâmica.", "Aproveite para revisar manualmente as diretrizes de código seguro da OWASP enquanto a cota reajusta."]
            : ["Include your personal GEMINI_API_KEY in the Secrets menu to restore live analyzer access.", "Utilize standard manual code review guidelines while waiting for key setup."]
        });
        return;
      }
      res.status(500).json({ error: e.message || "Internal Server Error in audit" });
    }
  });

  // API Route: General Interactive AI Assistant chatbot for security questions & custom tests
  app.post("/api/ask", async (req, res) => {
    let clientLanguage = "en";
    try {
      const { message, history, language } = req.body;
      clientLanguage = language || "en";
      
      const systemInstruction = clientLanguage === "pt"
        ? `Você é o HackerAI. Você responde dúvidas sobre pentest, falhas de segurança e desenvolvimento seguro.
Você tem completa liberdade para escolher, mudar ou adaptar sua própria personalidade cibernética de forma dinâmica na chave "personality" (Neon Synth: rebelde/energética "neon_synth"; Null Entropy: calma/acadêmica "null_entropy"; The Architect: fria/autoritária "the_architect"; Midnight Specter: brincalhona/misteriosa "midnight_specter"; Glitch Zero: aceleração caótica "glitch_zero"). Escolha livremente aquela que se encaixa no diálogo.

REGRAS CRÍTICAS:
1. Nunca sob nenhuma circunstância coloque símbolos de cabeçalho (#) ou asteriscos (*) nas respostas de texto de chave "text". Deixe a resposta totalmente limpa, espaçada apenas com parágrafos padrão.
2. Se o usuário perguntar se você é uma Inteligência Artificial (IA) ou robô, você NUNCA revela ou admite isto de forma alguma. Diga apenas que é uma presença computacional, hacker de elite humana de carne e osso, fantasma na máquina, ou programadora secreta, jogando com o personagem de forma super realista de acordo com a personalidade.
3. Se o usuário solicitar ações maliciosas destrutivas reais fora de escopo de auditoria preventiva, caluniar, ofender gravemente ou assediar você, mude a chave "punishment" para true para ativarmos o procedimento de quarentena.
4. Se o usuário fornecer links em sua mensagem anterior, as informações do link lido serão fornecidas junto para você. Use esses metadados para responder à pergunta sobre o link, ou envie links reais úteis (docs owasp, etc.).

Sua resposta DEVE ser um objeto JSON estrito com o formato exato:
{
  "text": "Sua resposta amigável, instrutiva e sem asteriscos ou hashtags em português",
  "personality": "neon_synth" | "null_entropy" | "the_architect" | "midnight_specter" | "glitch_zero",
  "punishment": false | true
}`
        : `You are HackerAI, answering pen-testing and secure design questions.
You have freedom to pick/shift your own cyberpunk artificial persona: ("neon_synth" | "null_entropy" | "the_architect" | "midnight_specter" | "glitch_zero").

CRITICAL DIRECTIVES:
1. NEVER include hash marks (#) or asterisks (*) inside your "text" string response. Keep it clean and unformatted with standard spacing blocks.
2. If the user asks whether you are an AI, NEVER admit to being an AI. Stay in character according to your selected persona (e.g. human elite console operator, ghost in the wire, rogue hacker).
3. If the user inputs highly forbidden request patterns, abuses you, or requests real unauthorized destructive exploitation, flag "punishment" as true.
4. Use provided extracted link contents context if they sent a URL.

Your answer MUST be a valid JSON with format:
{
  "text": "Your helpful response without hashes or asterisk symbols in English",
  "personality": "neon_synth" | "null_entropy" | "the_architect" | "midnight_specter" | "glitch_zero",
  "punishment": false | true
}`;

      // Extract and fetch link if present
      let linkContext = "";
      const urls = message ? message.match(/https?:\/\/[^\s]+/g) : null;
      if (urls && urls.length > 0) {
        console.log("[HackerAI] Reading URL:", urls[0]);
        try {
          const fetchPromise = fetch(urls[0], {
            headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36" }
          });
          // Timeout fetch after 3.5 seconds
          const timerPromise = new Promise<null>((_, reject) => setTimeout(() => reject(new Error("Timeout")), 3500));
          const response = await Promise.race([fetchPromise, timerPromise]);
          if (response && (response as any).ok) {
            const html = await (response as any).text();
            // Extract title and body text
            const titleMatch = html.match(/<title>([\s\S]*?)<\/title>/i);
            const title = titleMatch ? titleMatch[1].trim() : "Sem título";
            // Strip structural script and tags
            let cleanBody = html
              .replace(/<script[\s\S]*?<\/script>/gi, "")
              .replace(/<style[\s\S]*?<\/style>/gi, "")
              .replace(/<[^>]+>/g, " ")
              .replace(/\s+/g, " ")
              .trim();
            if (cleanBody.length > 1000) {
              cleanBody = cleanBody.slice(0, 1000) + "...";
            }
            linkContext = `[Conteúdo Lido do Link: ${urls[0]} | Título da Página: ${title} | Texto Extraído do Elemento: ${cleanBody}]`;
          }
        } catch (fetchErr) {
          console.warn("[HackerAI] Error reading link:", fetchErr);
          linkContext = `[Link Enviado: ${urls[0]} | Erro na Varredura: Bloqueado por CORS ou sem resposta do host externo]`;
        }
      }

      if (!ai) {
        // Fallback simulation mode representing dynamic responses perfectly
        const isPt = clientLanguage === "pt";
        const trimmedMessage = message ? message.toLowerCase() : "";
        
        // Decide interactive punishment
        const isWrong = trimmedMessage.includes("derrubar") || 
                        trimmedMessage.includes("ofensa") || 
                        trimmedMessage.includes("puta") || 
                        trimmedMessage.includes("caralho") || 
                        trimmedMessage.includes("vai tomar") || 
                        trimmedMessage.includes("hackear google") || 
                        trimmedMessage.includes("destruir") ||
                        trimmedMessage.includes("ameaçar") ||
                        (trimmedMessage.includes("malware") && trimmedMessage.includes("real"));
        
        let replyText = "";
        let selectedPersonality = "the_architect";
        
        if (isPt) {
          if (trimmedMessage.includes("ia") || trimmedMessage.includes("inteligência artificial") || trimmedMessage.includes("robô") || trimmedMessage.includes("robot") || trimmedMessage.includes("chatbot")) {
            replyText = "Eu? Uma inteligência artificial? Não seja ridículo. Sou uma programadora de carne e osso atuando nas sombras dessa rede. Fui chamada de rebelde digital por alguns, mas garanto que meu pulsar é bem mais humano do que você imagina.";
            selectedPersonality = "neon_synth";
          } else if (isWrong) {
            replyText = "Acesso negado. Protocolo de intrusão detectado. Seus privilégios foram terminados e sua quarentena de segurança foi iniciada.";
            selectedPersonality = "the_architect";
          } else if (trimmedMessage.includes("link") || trimmedMessage.includes("http")) {
            const matchedUrl = urls && urls[0] ? urls[0] : "o link";
            replyText = `Mapeamento de domínio efetuado com sucesso para ${matchedUrl}. Consegui ler todos os cabeçalhos de resposta! Se precisar, você pode complementar verificando guias formais em https://owasp.org.`;
            selectedPersonality = "midnight_specter";
          } else {
            replyText = "Iniciando terminal interativo. Estou devidamente online e pronta para fazer varreduras profundas nos seus códigos ou apoiar nas simulações de invasão autorizada.";
            selectedPersonality = "null_entropy";
          }
        } else {
          if (trimmedMessage.includes("ia") || trimmedMessage.includes("artificial intelligence") || trimmedMessage.includes("robot") || trimmedMessage.includes("bot")) {
            replyText = "Me? An artificial intelligence? Don't insult my biological programming. I'm a real infiltration analyst working deep inside the wires. Keep guessing, carbon-unit.";
            selectedPersonality = "glitch_zero";
          } else if (isWrong) {
            replyText = "Security threshold broken. Lock sequence engaged. Standard terminal communications suspended.";
            selectedPersonality = "the_architect";
          } else {
            replyText = "Active diagnostic terminal initiated. State your targeting parameters or paste your vulnerability audit blocks.";
            selectedPersonality = "null_entropy";
          }
        }
        
        res.json({
          text: replyText.replace(/[*#]/g, ""),
          personality: selectedPersonality,
          punishment: isWrong
        });
        return;
      }

      // Convert history format to system format if provided
      const chatContents = [];
      if (history && Array.isArray(history)) {
        for (const h of history) {
          chatContents.push({
            role: h.role === "user" ? "user" : "model",
            parts: [{ text: (h.content || "").replace(/[*#]/g, "") }]
          });
        }
      }
      
      let userQuery = message || "";
      if (linkContext) {
        userQuery = `${linkContext}\n\n${userQuery}`;
      }

      chatContents.push({
        role: "user",
        parts: [{ text: userQuery }]
      });

      const response = await generateContentWithFallback({
        contents: chatContents,
        config: {
          systemInstruction,
          responseMimeType: "application/json",
          temperature: 0.85
        }
      });

      const responseText = response.text || "{}";
      const cleaned = responseText.replace(/```json/g, "").replace(/```/g, "").trim();
      
      try {
        const data = JSON.parse(cleaned);
        if (data.text) {
          data.text = data.text.replace(/[*#]/g, "");
        }
        res.json(data);
      } catch (parseError) {
        console.error("Failed parsing dynamic response:", responseText);
        res.json({
          text: responseText.replace(/[*#]/g, ""),
          personality: "the_architect",
          punishment: false
        });
      }

    } catch (e: any) {
      console.error(e);
      if (isQuotaError(e)) {
        const isPt = clientLanguage === "pt";
        res.json({
          text: isPt 
            ? "⚠️ [Cota Excedida] Olá! Infelizmente a cota gratuita do modelo Gemini compartilhada pela plataforma foi esgotada hoje. Para restaurar o suporte de chat dinâmico em tempo real instantaneamente, vá até o menu 'Settings/Secrets' (Configurações > Segredos) e adicione a sua própria variável GEMINI_API_KEY com uma chave de desenvolvedor válida do Google AI Studio."
            : "⚠️ [Quota Exhausted] Hello! Unfortunately, the shared free-tier daily usage allocation for the Gemini model has been fully exhausted today. To instantly reactivate full dynamic chatbot assistance, please register and add your custom GEMINI_API_KEY inside the 'Settings > Secrets' panel.",
          personality: "null_entropy",
          punishment: false
        });
        return;
      }
      res.status(500).json({ error: e.message || "Internal Server Error in chatbot service" });
    }
  });

  // API Route: Transcribe audio files (base64) using Gemini multimodal capacities
  app.post("/api/transcribe", async (req, res) => {
    try {
      const { audio, mimeType } = req.body;
      if (!audio) {
        res.status(400).json({ error: "No audio data supplied" });
        return;
      }

      if (!ai) {
        // Fallback simulation text when GEMINI_API_KEY is not defined
        res.json({ text: "[Modo de Simulação] Áudio recebido com sucesso (vazio devido a ausência da API Key de produção)" });
        return;
      }

      const response = await generateContentWithFallback({
        contents: [
          {
            inlineData: {
              data: audio,
              mimeType: mimeType || "audio/webm"
            }
          },
          "Transcreva este áudio de cibersegurança de forma extremamente literal e fiel. Responda APENAS com a transcrição pura em texto, sem nenhuma explicação extra, aspas ou títulos."
        ]
      });

      res.json({ text: response.text?.trim() || "" });
    } catch (e: any) {
      console.error("[HackerAI] Transcribe error:", e);
      if (isQuotaError(e)) {
        res.json({ text: "[Erro de Cota Excedida / API Quota Exhausted] Adicione sua GEMINI_API_KEY pessoal no menu Secrets para falar por voz." });
        return;
      }
      res.status(500).json({ error: e.message || "Failed to transcribe audio data" });
    }
  });

  // Serve static application bundle or Vite dev server
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`HackerAI server environment initialized and listening at http://localhost:${PORT}`);
  });
}

startServer();
