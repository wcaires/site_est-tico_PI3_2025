import * as functions from "firebase-functions";
import * as admin from "firebase-admin";
import {v4 as uuidv4} from "uuid"; 
import * as QRCode from "qrcode";
import * as corsLib from "cors";

admin.initializeApp();
const db = admin.firestore();
const cors = corsLib.default({origin: true});

// --- Constantes para o controle de tempo e consultas ---
const MAX_CONSULTATIONS = 3;
const LOGIN_TOKEN_EXPIRATION_MINUTES = 1; // 1 minuto conforme o requisito

/**
 * Funções exportadas para o Firebase.
 */

export const gerarQrCode = functions.https.onRequest((req, res) => { // Renomeado para gerarQrCode
  cors(req, res, async () => {
    if (req.method !== "POST") {
      res.status(405).send({error: "Método não permitido. Use POST."});
      return;
    }

    const {siteUrl, apiKey} = req.body;

    if (!siteUrl || !apiKey) {
      res.status(400).json({
        error: "Parâmetros 'siteUrl' e 'apiKey' são obrigatórios.",
      });
      return;
    }

    try {
      const partnerDocRef = db.collection("partners").doc(siteUrl);
      const partnerDoc = await partnerDocRef.get();

      if (!partnerDoc.exists) {
        console.warn(`Tentativa de acesso de site não cadastrado: ${siteUrl}`);
        res.status(403).json({
          error: "Site parceiro não encontrado ou não autorizado.",
        });
        return;
      }

      const partnerData = partnerDoc.data();
      if (partnerData?.apiKey !== apiKey) {
        console.warn(`Tentativa de acesso com API Key inválida para: ${siteUrl}`);
        res.status(403).json({error: "API Key inválida para este site parceiro."});
        return;
      }

      // 2. Gerar o loginToken (256 caracteres conforme requisito) usando UUIDs
      const loginToken =
        uuidv4().replace(/-/g, "") +
        uuidv4().replace(/-/g, "") +
        uuidv4().replace(/-/g, "") +
        uuidv4().replace(/-/g, "") +
        uuidv4().replace(/-/g, "") +
        uuidv4().replace(/-/g, "") +
        uuidv4().replace(/-/g, "") +
        uuidv4().replace(/-/g, ""); // Garante 256 caracteres

      const createdAt = admin.firestore.FieldValue.serverTimestamp();

      // 3. Cadastrar o documento na coleção 'login'
      await db.collection("login").doc(loginToken).set({
        siteUrl,
        apiKey,
        createdAt,
        loginToken,
        status: "pending",
        consultationCount: 0,
        lastConsultation: null,
        user: null,
        loggedInAt: null,
      });

      // 4. Gerar o QR Code (conteúdo é apenas o loginToken)
      const qrCodeBase64 = await QRCode.toDataURL(loginToken);

      // 5. Retornar a imagem Base64 do QR Code e o loginToken
      res.status(200).json({
        qrCodeImageBase64: qrCodeBase64.split(",")[1],
        loginToken: loginToken,
      });
    } catch (error) {
      console.error("Erro em gerarQrCode:", error);
      res.status(500).json({error: "Erro interno do servidor ao gerar QR Code."});
    }
  });
});

export const checkLoginStatus = functions.https.onRequest((req, res) => { 
  cors(req, res, async () => {
    if (req.method !== "GET") {
      res.status(405).send({error: "Método não permitido. Use GET."});
      return;
    }

    const loginToken = req.query.loginToken as string;

    if (!loginToken) {
      res.status(400).json({error: "Parâmetro 'loginToken' é obrigatório."});
      return;
    }

    try {
      const loginDocRef = db.collection("login").doc(loginToken);
      const loginDoc = await loginDocRef.get();

      if (!loginDoc.exists) {
        res.status(404).json({
          status: "expired_or_not_found",
          message: "Token de login não encontrado ou já expirado/excluído.",
        });
        return;
      }

      const data = loginDoc.data();
      if (!data) {
        res.status(500).json({error: "Dados do documento de login ausentes."});
        return;
      }

      const now = admin.firestore.Timestamp.now();
      const createdAt = data.createdAt as admin.firestore.Timestamp;
      const consultationCount = data.consultationCount || 0;

      const timeElapsed =
        (now.toMillis() - createdAt.toMillis()) / (1000 * 60);

      if (timeElapsed > LOGIN_TOKEN_EXPIRATION_MINUTES) {
        await loginDocRef.delete();
        res.status(410).json({
          status: "expired",
          message: "Token de login expirado por tempo.",
        });
        return;
      }

      if (consultationCount >= MAX_CONSULTATIONS) {
        await loginDocRef.delete();
        res.status(429).json({
          status: "too_many_requests",
          message: "Limite de consultas excedido para este token.",
        });
        return;
      }

      await loginDocRef.update({
        consultationCount: admin.firestore.FieldValue.increment(1),
        lastConsultation: now,
      });

      if (data.user && data.loggedInAt) {
        res.status(200).json({
          status: "loggedIn",
          uid: data.user,
          loggedInAt: data.loggedInAt.toDate().toISOString(),
        });
      } else {
        res.status(200).json({
          status: "pending",
          message: "Aguardando autenticação do usuário no aplicativo SuperID.",
        });
      }
    } catch (error) {
      console.error("Erro em checkLoginStatus:", error);
      res.status(500).json({error: "Erro interno do servidor ao verificar status do login."});
    }
  });
});

export const confirmLogin = functions.https.onRequest((req, res) => {
  cors(req, res, async () => {
    if (req.method !== "POST") {
      res.status(405).send({error: "Método não permitido. Use POST."});
      return;
    }

    const {loginToken, uid} = req.body;

    if (!loginToken || !uid) {
      res.status(400).json({error: "Parâmetros 'loginToken' e 'uid' são obrigatórios."});
      return;
    }

    try {
      const loginDocRef = db.collection("login").doc(loginToken);
      const loginDoc = await loginDocRef.get();

      if (!loginDoc.exists) {
        res.status(404).json({error: "Token de login não encontrado ou expirado."});
        return;
      }

      const data = loginDoc.data();
      if (data?.user) {
        res.status(409).json({error: "Este token já foi usado para login."});
        return;
      }

      await loginDocRef.update({
        user: uid,
        loggedInAt: admin.firestore.FieldValue.serverTimestamp(),
        status: "completed",
      });

      res.status(200).json({message: "Login confirmado com sucesso!"});
    } catch (error) {
      console.error("Erro em confirmLogin:", error);
      res.status(500).json({error: "Erro interno do servidor ao confirmar login."});
    }
  });
});