<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Telegram\Bot\Api;

class TelegramController extends Controller
{
    public function webhook(Request $request)
    {
        $telegram = new Api(env('TELEGRAM_TOKEN'));
        $update = $telegram->getWebhookUpdate();
        $message = $update->getMessage();

        if($message->getDocument()){
            $document = $message->getDocument();
            $fileId = $document->getFileId();
            $fileName = $document->getFileName();

            // telegramdan file manzilini olish

            $file = $telegram->getFile(['file_id' => $fileId]);
            $filePath = $file->getFilePath();
            $fileURL = "https://api.telegram.org/file/bot" . env('TELEGRAM_BOT_TOKEN') . "/$filePath";

            // fileni yuklab olish

            $localPtah = storage_path('app/public/'. $fileName );
            file_put_contents($localPath, file_get_contents($fileUrl));

            // VirusTotal orqali skanerlash
            $resultText = $this->scanWithVirusTotal($localPath);

            // Javob yuborish
            $telegram->sendMessage([
                'chat_id' => $chatId,
                'text' => $resultText,
            ]);

            // Faylni o‘chirish
            unlink($localPath);

            return response('ok');
        }

        if($message && $message->getText()){
            $text = strtolower($message->getText());
            $chat_id = $message->getChat()->getId();

            $telegram->sendMessage([
                'chat_id' => $chat_id,
                'text' => "📎 Menga ilovani (APK fayl) yuboring, men uni tekshiraman."
            ]);
        }

        return response('ok');
    }

    public function scanWithVirusTotal($filePath)
    {
        $apiKey = env('VIRUSTOTAL_API_KEY');

        // Faylni VirusTotal’ga yuborish
        $response = Http::withHeaders([
            'x-apikey' => $apiKey,
        ])->attach(
            'file', file_get_contents($filePath), basename($filePath)
        )->post('https://www.virustotal.com/api/v3/files');

        $data = $response->json();

        if (isset($data['data']['id'])) {
            $analysisId = $data['data']['id'];

            // 15 soniya kutamiz
            sleep(15);

            // Natijani olish
            $result = Http::withHeaders([
                'x-apikey' => $apiKey,
            ])->get("https://www.virustotal.com/api/v3/analyses/{$analysisId}");

            $stats = $result['data']['attributes']['stats'];

            return "🛡️ Tekshiruv natijasi:\n"
                . "- Xavfli: {$stats['malicious']} ta\n"
                . "- Ehtimolli xavfli: {$stats['suspicious']} ta\n"
                . "- Toza: {$stats['harmless']} ta\n"
                . "\n⏳ VirusTotal’da tahlil tugallandi.";
        }

        return "❌ Tahlil qilishda xatolik yuz berdi. Iltimos, qayta urinib ko‘ring.";
    }

}
