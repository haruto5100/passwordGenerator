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
//  C-1: AIアドバイスのテンプレート定義（セキュリティ知識の注入）
// ----------------------------------------------------
const ADVICE_TEMPLATES = {
    // パスワードが短すぎる場合（最低12文字未満）
    TOO_SHORT: (length) => `
        改善点：長さの強化 - パスワードが${length}文字と短すぎます。16文字以上にしましょう。
    `,
    // 文字種が少ない場合
    LOW_COMPLEXITY: (missingTypes) => `
        改善点：複雑さの追加 - ${missingTypes.join('と')}が含まれていません。文字種の多様性はエントロピーを劇的に増加させます。最低でも英大文字、小文字、数字、記号の3種類以上を組み合わせましょう。
    `,
    // 連続する文字や辞書語のようなパターンがある場合（エントロピーで間接的に警告）
    WEAK_PATTERN: `
        改善点：パターン排除 - ユーザーが自作したパスワードの場合、誕生日やペットの名前など、推測されやすい辞書語や連続パターンの使用は避けてください。生成したパスワードであれば、そのまま利用しても問題ありません。
    `,
    // 非常に強力な場合
    VERY_STRONG: `
        評価：非常に安全 - このパスワードは高いエントロピー（情報量）を持ち、ブルートフォース攻撃に対する耐性が非常に高いと評価されました。この強度を維持しましょう。
    `
};

// ----------------------------------------------------
// フェーズA: セキュアなパスワードを生成するメイン関数
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
//  フェーズB: パスワード強度（エントロピー）を計算する関数群
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
//  C-2: ターゲット別アドバイス生成ロジック
// ----------------------------------------------------
function getTargetedAdvice(password, entropy) {
    let adviceList = [];
    const length = password.length;
    
    // 1. 長さのチェック
    if (length < 12) {
        adviceList.push(ADVICE_TEMPLATES.TOO_SHORT(length));
    }
    
    // 2. 文字種のチェック
    let missingTypes = [];
    if (!/[a-z]/.test(password)) missingTypes.push('英小文字');
    if (!/[A-Z]/.test(password)) missingTypes.push('英大文字');
    if (!/[0-9]/.test(password)) missingTypes.push('数字');
    if (!/[^a-zA-Z0-9]/.test(password)) missingTypes.push('記号');

    if (missingTypes.length > 0 && missingTypes.length < 4) {
        adviceList.push(ADVICE_TEMPLATES.LOW_COMPLEXITY(missingTypes));
    }

    // 3. 一般的なパターンの警告（エントロピーが低い場合）
    if (entropy < 70) {
        adviceList.push(ADVICE_TEMPLATES.WEAK_PATTERN);
    }

    // 全てのアドバイスを結合して返す
    return adviceList.length > 0 
           ? adviceList.join('<br><br>') 
           : ADVICE_TEMPLATES.VERY_STRONG;
}


// ----------------------------------------------------
// メイン処理: 強度分析と出力
// ----------------------------------------------------
function checkPasswordStrength(password) {
    const strengthOutput = document.getElementById('strengthOutput');
    const aiAdviceOutput = document.getElementById('aiAdviceOutput');

    // エラーチェック
    if (password === "文字種を一つ以上選択してください。" || password.length === 0 || password === "生成ボタンを押してください") {
        strengthOutput.innerHTML = `<h4>パスワード強度分析</h4><p style="color:#dc3545;">パスワードが生成されていません。条件を確認してください。</p>`;
        aiAdviceOutput.innerHTML = ''; 
        return;
    }

    const entropy = calculateEntropy(password);
    const crackTime = getCrackTimeEstimate(entropy);

    let safetyLevel = '';
    let color = '';
    let adviceHTML = '';

    // エントロピーによる強度分類
    if (entropy >= 80) {
        safetyLevel = "非常に強力 (Very Strong)";
        color = "#28a745"; // 緑
        adviceHTML = ADVICE_TEMPLATES.VERY_STRONG;
    } else if (entropy >= 60) {
        safetyLevel = "安全 (Strong)";
        color = "#ffc107"; // 黄色
        adviceHTML = getTargetedAdvice(password, entropy); 
    } else {
        safetyLevel = "注意が必要 (Weak)";
        color = "#dc3545"; // 赤
        adviceHTML = getTargetedAdvice(password, entropy);
    }

    // --- 強度分析の結果を出力 ---
    strengthOutput.innerHTML = `
        <h4>パスワード強度分析 (セキュリティ評価)</h4>
        <p>エントロピー: <strong>${entropy.toFixed(2)} ビット</strong></p>
        <p>攻撃者が解読にかかる推定時間 (GPUクラスタ想定): <strong style="color: ${color};">${crackTime}</strong></p>
        <p>総合評価: <strong style="color: ${color};">${safetyLevel}</strong></p>
    `;
    
    // --- AIアドバイスを出力 ---
    aiAdviceOutput.innerHTML = `
        <div class="ai-advice-box">
            <h4>セキュリティ改善アドバイス</h4>
            <p>${adviceHTML}</p>
        </div>
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
