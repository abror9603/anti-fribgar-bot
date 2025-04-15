<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Telegram\Bot\Api;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
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
            $chatId = $message->getChat()->getId();
            // telegramdan file manzilini olish

            $file = $telegram->getFile(['file_id' => $fileId]);
            $filePath = $file->getFilePath();
            $fileURL = "https://api.telegram.org/file/bot" . env('TELEGRAM_TOKEN') . "/$filePath";

            // fileni yuklab olish

            $localPath = storage_path('app/public/'. $fileName );
            file_put_contents($localPath, file_get_contents($fileURL));

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

            if (filter_var($text, FILTER_VALIDATE_URL)) {
                $resultText = $this->scanUrlWithVirusTotal($text);
        
                $telegram->sendMessage([
                    'chat_id' => $chat_id,
                    'text' => $resultText,
                ]);
            } 

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

        // Log::info(["apk" => $response]);

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
            Log::info(["url" => $stats]);
            return "🛡️ Tekshiruv natijasi:\n"
                . "- Xavfli: {$stats['malicious']} ta\n"
                . "- Ehtimolli xavfli: {$stats['suspicious']} ta\n"
                . "- Toza: {$stats['harmless']} ta\n"
                . "\n⏳ VirusTotal’da tahlil tugallandi.";
        }

        return "❌ Tahlil qilishda xatolik yuz berdi. Iltimos, qayta urinib ko‘ring.";
    }

    public function scanUrlWithVirusTotal($url)
    {
        $apiKey = env('VIRUSTOTAL_API_KEY');

        // VirusTotal API'ga URL yuborish
        $response = Http::withHeaders([
            'x-apikey' => $apiKey,
            'Content-Type' => 'application/x-www-form-urlencoded',
        ])->asForm()->post('https://www.virustotal.com/api/v3/urls', [
            'url' => $url
        ]);

       

        $data = $response->json();

        if (isset($data['data']['id'])) {
            $analysisId = $data['data']['id'];

            // 10 soniya kutish
            sleep(10);

            // Tahlil natijasini olish
            $result = Http::withHeaders([
                'x-apikey' => $apiKey,
            ])->get("https://www.virustotal.com/api/v3/analyses/{$analysisId}");

            $stats = $result['data']['attributes']['stats'];
            Log::info(["url" => $stats]);
            return "🌐 URL tekshiruv natijasi:\n"
                . "- Xavfli: {$stats['malicious']} ta\n"
                . "- Ehtimolli xavfli: {$stats['suspicious']} ta\n"
                . "- Toza: {$stats['harmless']} ta\n"
                . "\n🔗 Siz yuborgan URL: {$url}";
        }

        return "❌ URL tahlilida xatolik. Qayta urinib ko‘ring.";
    }

}
