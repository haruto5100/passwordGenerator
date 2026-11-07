// パスワードに使用する文字種を定義
const CHARS = {
    LOWER: 'abcdefghijklmnopqrstuvwxyz',
    UPPER: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    NUMBER: '0123456789',
    SYMBOL: '!@#$%^&*()_+-=[]{}|;:",.<>?/`~',
};

// 想定する攻撃速度 (例: 1秒あたり1兆回 (10^12) の推測)
const GUESSES_PER_SECOND = Math.pow(10, 12); 

// ----------------------------------------------------
// 💻 フェーズA: セキュアなパスワードを生成するメイン関数
// ----------------------------------------------------
function generateSecurePassword(length, options) {
    let characterSet = '';
    
    // 選択された文字種に基づいて使用する文字セットを構築
    if (options.includeLower) characterSet += CHARS.LOWER;
    if (options.includeUpper) characterSet += CHARS.UPPER;
    if (options.includeNumbers) characterSet += CHARS.NUMBER;
    if (options.includeSymbols) characterSet += CHARS.SYMBOL;

    // どの文字種も選択されていない場合はエラーメッセージを返す
    if (characterSet.length === 0) {
        return "文字種を一つ以上選択してください。";
    }

    const setLength = characterSet.length;
    let password = '';

    // 暗号学的に安全な乱数生成器を使用 (Web Crypto API)
    const randomArray = new Uint8Array(length);
    window.crypto.getRandomValues(randomArray); // 安全な乱数を生成

    // 生成された乱数配列を文字セットのインデックスに変換
    for (let i = 0; i < length; i++) {
        const randomIndex = randomArray[i] % setLength;
        password += characterSet.charAt(randomIndex);
    }

    return password;
}

// ----------------------------------------------------
// 📊 フェーズB: パスワード強度（エントロピー）を計算する関数群
// ----------------------------------------------------

/**
 * パスワードに含まれる文字種から、使用可能な文字数（ベースR）を計算する
 */
function calculateCharacterSetSize(password) {
    let R = 0; 
    
    // 各文字種が含まれているかチェックし、Rを計算
    if (/[a-z]/.test(password)) R += CHARS.LOWER.length;
    if (/[A-Z]/.test(password)) R += CHARS.UPPER.length;
    if (/[0-9]/.test(password)) R += CHARS.NUMBER.length;
    // 上記に含まれない特殊文字（記号）が存在するかをチェック
    if (/[^a-zA-Z0-9]/.test(password)) R += CHARS.SYMBOL.length;

    // Rが0の場合は、安全のために最低限の文字セット（小文字のみ）のサイズを設定
    return R > 0 ? R : CHARS.LOWER.length;
}

/**
 * パスワードのエントロピー（ビット数）を計算する: E = L * log2(R)
 */
function calculateEntropy(password) {
    const L = password.length; // パスワードの長さ
    const R = calculateCharacterSetSize(password); // 使用文字種の数 (ベースR)
    
    // Math.log(R) / Math.log(2) で log2(R) を実現
    return L * (Math.log(R) / Math.log(2));
}

/**
 * エントロピーに基づいて、クラックにかかる推定時間を人間が読める形式で返す
 */
function getCrackTimeEstimate(entropy) {
    // 可能な組み合わせ総数 = 2^E
    const combinations = Math.pow(2, entropy);
    
    // クラックにかかる秒数
    const secondsToCrack = combinations / GUESSES_PER_SECOND;

    const SECONDS = 1;
    const MINUTES = SECONDS * 60;
    const HOURS = MINUTES * 60;
    const DAYS = HOURS * 24;
    const MONTHS = DAYS * 30; // 概算
    const YEARS = DAYS * 365;

    if (secondsToCrack < 1) return "瞬時 (1秒未満)";
    if (secondsToCrack < MINUTES) return `${Math.floor(secondsToCrack)} 秒`;
    if (secondsToCrack < HOURS) return `${Math.floor(secondsToCrack / MINUTES)} 分`;
    if (secondsToCrack < DAYS) return `${Math.floor(secondsToCrack / HOURS)} 時間`;
    if (secondsToCrack < MONTHS) return `${Math.floor(secondsToCrack / DAYS)} 日`;
    if (secondsToCrack < YEARS) return `${Math.floor(secondsToCrack / MONTHS)} ヶ月`;
    
    // 非常に長い期間の場合は、年単位で表示
    return `${(secondsToCrack / YEARS).toLocaleString(undefined, { maximumFractionDigits: 1 })} 年`;
}


// ----------------------------------------------------
// メイン処理: 強度分析と出力
// ----------------------------------------------------
function checkPasswordStrength(password) {
    const strengthOutput = document.getElementById('strengthOutput');

    // エラーチェック
    if (password === "文字種を一つ以上選択してください。" || password.length === 0 || password === "生成ボタンを押してください") {
        strengthOutput.innerHTML = `<h4>パスワード強度分析</h4><p style="color:#dc3545;">パスワードが生成されていません。条件を確認してください。</p>`;
        return;
    }

    const entropy = calculateEntropy(password);
    const crackTime = getCrackTimeEstimate(entropy);

    let safetyLevel = '';
    let color = '';

    // エントロピーによる強度分類
    if (entropy >= 80) {
        safetyLevel = "強力";
        color = "#28a745"; // 緑
    } else if (entropy >= 60) {
        safetyLevel = "普通";
        color = "#ffc107"; // 黄色
    } else {
        safetyLevel = "脆弱";
        color = "#dc3545"; // 赤
    }

    // --- 強度分析の結果を出力 ---
    strengthOutput.innerHTML = `
        <h4>強度</h4>
        <p><strong style="color: ${color};">${safetyLevel}</strong></p>
    `;
}

// ----------------------------------------------------
// イベントリスナーの設定
// ----------------------------------------------------

document.getElementById('generateButton').addEventListener('click', () => {
    const length = parseInt(document.getElementById('passwordLength').value);
    
    // パスワードの長さのバリデーション
    if (length < 8 || length > 64 || isNaN(length)) {
        alert("パスワードの長さは8文字から64文字の間に設定してください。");
        return;
    }

    // 選択されたオプションの取得
    const options = {
        includeLower: document.getElementById('includeLower').checked,
        includeUpper: document.getElementById('includeUpper').checked,
        includeNumbers: document.getElementById('includeNumbers').checked,
        includeSymbols: document.getElementById('includeSymbols').checked,
    };
    
    const newPassword = generateSecurePassword(length, options);
    
    // 結果の表示
    document.getElementById('generatedPassword').value = newPassword;
    
    // 強度分析関数を呼び出す
    checkPasswordStrength(newPassword); 
});

// コピーボタンの実装
document.getElementById('copyButton').addEventListener('click', () => {
    const passwordField = document.getElementById('generatedPassword');
    
    if (passwordField.value.length > 0 && passwordField.value !== "文字種を一つ以上選択してください。" && passwordField.value !== "生成ボタンを押してください") {
        
        if (navigator.clipboard) {
            navigator.clipboard.writeText(passwordField.value)
                .then(() => alert('パスワードがクリップボードにコピーされました！'))
                .catch(err => {
                    // Fallback attempt
                    passwordField.select();
                    document.execCommand('copy');
                    alert('パスワードがクリップボードにコピーされました！');
                });
        } else {
             // Fallback for older browsers
             passwordField.select();
             document.execCommand('copy');
             alert('パスワードがクリップボードにコピーされました！');
        }
    } else {
        alert('コピーするパスワードがありません。');
    }
});