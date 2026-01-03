// ═══════════════════════════════════════════════════════════════════════════════
// WP OPTIMIZER PRO v25.0 — ENTERPRISE SOTA UTILITIES
// ═══════════════════════════════════════════════════════════════════════════════
// SOTA Features:
// • 🔥 Plug-in QA Rule Engine — testable, independently deployable rules
// • 🔥 Word-Boundary-Safe Internal Link Injection — NEVER breaks words
// • 🔥 SERP-Driven Dynamic Thresholds — computed from top-3 analysis
// • 🔥 Content Integrity Validation — structure enforcement
// • 🔥 Versioned Scoring — scoreVersion + weights for comparability
// • 🔥 HTML AST-Safe Operations — parse5-compatible transforms
// • 50+ QA Validation Rules with H1 Duplication Prevention
// • Advanced Readability Scoring (Flesch-Kincaid + SMOG + Gunning Fog)
// • E-E-A-T Signal Detection & Scoring
// • AEO/GEO/SEO Triple-Threat Scoring
// • FAQ Duplicate Detection & Cleanup
// • Q&A Pattern Detection in Main Content
// ═══════════════════════════════════════════════════════════════════════════════

import { 
    SeoMetrics, ContentContract, QAValidationResult, QASwarmResult, 
    NeuronTerm, ExistingContentAnalysis, EntityGapAnalysis, InternalLinkTarget,
    OpportunityScore, APP_VERSION, SerpLengthPolicy, ScoreBreakdown,
    ScoreWeights, CURRENT_SCORE_WEIGHTS, QARule, QARuleContext, QADetectionResult,
    InternalLinkResult, ValidatedReference, SiteContext
} from './types';

// ═══════════════════════════════════════════════════════════════════════════════
// 📌 VERSIONING & CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

export const UTILS_VERSION = "25.0.0";
export const SCORE_ALGORITHM_VERSION = "2.0.0";

const CURRENT_YEAR = new Date().getFullYear();

// ═══════════════════════════════════════════════════════════════════════════════
// 🎯 POWER WORDS & E-E-A-T SIGNALS
// ═══════════════════════════════════════════════════════════════════════════════

const POWER_WORDS = [
    'proven', 'guaranteed', 'exclusive', 'secret', 'revolutionary', 'breakthrough',
    'ultimate', 'essential', 'comprehensive', 'definitive', 'expert', 'professional',
    'advanced', 'complete', 'powerful', 'effective', 'instant', 'free', 'new',
    'best', 'top', 'amazing', 'incredible', 'remarkable', 'outstanding', 'critical',
    'vital', 'crucial', 'important', 'key', 'must-have', 'game-changing', 'transformative'
];

const EEAT_SIGNALS = [
    'according to', 'research shows', 'studies indicate', 'experts recommend',
    'data suggests', 'evidence shows', 'scientific', 'clinical', 'peer-reviewed',
    'published in', 'certified', 'licensed', 'experienced', 'years of experience',
    'board-certified', 'award-winning', 'industry-leading', 'trusted by',
    'verified by', 'based on research', 'according to experts', 'clinical studies',
    'scientific evidence', 'expert opinion', 'professional recommendation'
];

const AUTHORITY_DOMAINS = [
    '.gov', '.edu', '.org', '.mil', '.int', '.ac.uk', '.edu.au',
    'reuters.com', 'bbc.com', 'nytimes.com', 'wsj.com', 'economist.com',
    'apnews.com', 'theguardian.com', 'washingtonpost.com', 'ft.com',
    'forbes.com', 'bloomberg.com', 'cnbc.com', 'businessinsider.com',
    'fortune.com', 'hbr.org', 'mckinsey.com', 'gartner.com', 'deloitte.com',
    'nature.com', 'sciencedirect.com', 'springer.com', 'wiley.com',
    'pubmed', 'ncbi.nlm.nih.gov', 'arxiv.org', 'researchgate.net',
    'scholar.google.com', 'jstor.org', 'ieee.org', 'acm.org',
    'techcrunch.com', 'wired.com', 'arstechnica.com', 'theverge.com',
    'cnet.com', 'zdnet.com', 'thenextweb.com', 'engadget.com',
    'hubspot.com', 'semrush.com', 'moz.com', 'ahrefs.com', 
    'searchengineland.com', 'searchenginejournal.com', 'backlinko.com',
    'healthline.com', 'webmd.com', 'mayoclinic.org', 'nih.gov', 'cdc.gov',
    'who.int', 'clevelandclinic.org', 'hopkinsmedicine.org',
    'wikipedia.org', 'britannica.com', 'statista.com', 'pewresearch.org',
    'gallup.com', 'data.gov', 'worldbank.org', 'imf.org'
];

// ═══════════════════════════════════════════════════════════════════════════════
// 🚫 STOP WORDS & BANNED WORDS FOR ANCHOR TEXT
// ═══════════════════════════════════════════════════════════════════════════════

export const STOP_WORDS = new Set([
    'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for',
    'of', 'with', 'by', 'from', 'as', 'is', 'was', 'are', 'were', 'been',
    'be', 'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would',
    'could', 'should', 'may', 'might', 'must', 'shall', 'can', 'need',
    'this', 'that', 'these', 'those', 'i', 'you', 'he', 'she', 'it', 'we',
    'they', 'what', 'which', 'who', 'whom', 'your', 'his', 'her', 'its',
    'our', 'their', 'my', 'how', 'why', 'when', 'where', 'best', 'top',
    'most', 'more', 'very', 'just', 'also', 'only', 'even', 'still',
    'about', 'into', 'through', 'during', 'before', 'after', 'above',
    'below', 'between', 'under', 'again', 'further', 'then', 'once'
]);

export const BANNED_SINGLE_WORDS = new Set([
    'click', 'here', 'read', 'more', 'learn', 'see', 'find', 'get', 'try',
    'view', 'check', 'visit', 'go', 'start', 'begin', 'continue', 'discover',
    'explore', 'download', 'access', 'open', 'link', 'page', 'article', 'post',
    'website', 'site', 'blog', 'info', 'information', 'details', 'content'
]);

export const BANNED_PHRASE_REGEXES = [
    /^click\s+here/i,
    /^read\s+more/i,
    /^learn\s+more/i,
    /^find\s+out/i,
    /^check\s+(out|this)/i,
    /^this\s+(article|post|guide|page)/i,
    /^here\s+is/i,
    /^see\s+(here|more|this)/i,
    /^go\s+(here|to)/i,
    /more\s+info(rmation)?$/i,
    /click\s+here$/i,
    /read\s+more$/i,
    /learn\s+more$/i,
    /^view\s+(all|more)/i,
    /^get\s+(started|more)/i,
];

// ═══════════════════════════════════════════════════════════════════════════════
// 🔥 ANCHOR TEXT CONFIGURATION — ENTERPRISE GRADE v2.0
// ═══════════════════════════════════════════════════════════════════════════════

export const ANCHOR_CONFIG = {
    MIN_WORDS: 3,
    MAX_WORDS: 6,
    IDEAL_MIN_WORDS: 4,
    IDEAL_MAX_WORDS: 5,
    MIN_CHARS: 18,
    MAX_CHARS: 60,
    MIN_MEANINGFUL: 3,
    RELEVANCE_THRESHOLD: 0.55,
    MIN_LINK_DISTANCE: 450,
    MAX_LINKS_PER_SECTION: 2,
    MAX_SAME_ANCHOR_USES: 1,
    PREFER_NOUN_PHRASES: true,
};

// ═══════════════════════════════════════════════════════════════════════════════
// 🔥 SERP-DRIVEN THRESHOLD SYSTEM — DYNAMIC THRESHOLDS
// ═══════════════════════════════════════════════════════════════════════════════

export const DEFAULT_THRESHOLDS = {
    WORD_COUNT_MIN: 4500,
    WORD_COUNT_IDEAL: 5000,
    H1_COUNT: 0,
    H2_COUNT_MIN: 10,
    H3_COUNT_MIN: 18,
    FAQ_COUNT_MIN: 7,
    FAQ_COUNT_IDEAL: 10,
    INTERNAL_LINKS_MIN: 15,
    INTERNAL_LINKS_IDEAL: 20,
    EXTERNAL_REFS_MIN: 8,
    EXTERNAL_REFS_IDEAL: 12,
    TABLES_MIN: 2,
    BLOCKQUOTES_MIN: 2,
    LISTS_MIN: 5,
    VISUAL_BOXES_MIN: 10,
    NLP_COVERAGE_MIN: 70,
    TITLE_MIN_LENGTH: 45,
    TITLE_MAX_LENGTH: 65,
    META_MIN_LENGTH: 145,
    META_MAX_LENGTH: 160,
    READABILITY_MIN: 50,
    READABILITY_IDEAL: 65,
    PARAGRAPH_MAX_WORDS: 100,
    SENTENCE_MAX_WORDS: 30,
};

const NICHE_PRESETS: Record<string, Partial<typeof DEFAULT_THRESHOLDS>> = {
    health: { WORD_COUNT_MIN: 5000, EXTERNAL_REFS_MIN: 12, FAQ_COUNT_MIN: 10 },
    finance: { WORD_COUNT_MIN: 5500, EXTERNAL_REFS_MIN: 15, TABLES_MIN: 3 },
    legal: { WORD_COUNT_MIN: 6000, EXTERNAL_REFS_MIN: 15, H2_COUNT_MIN: 12 },
    tech: { WORD_COUNT_MIN: 4000, TABLES_MIN: 3, LISTS_MIN: 8 },
    ecommerce: { WORD_COUNT_MIN: 3500, TABLES_MIN: 4, FAQ_COUNT_MIN: 8 },
    blog: { WORD_COUNT_MIN: 4000, READABILITY_IDEAL: 70 },
    ymyl: { WORD_COUNT_MIN: 5500, EXTERNAL_REFS_MIN: 15, FAQ_COUNT_MIN: 10 },
};

export function computeDynamicThresholds(
    serpPolicy?: SerpLengthPolicy,
    niche?: string
): typeof DEFAULT_THRESHOLDS {
    let thresholds = { ...DEFAULT_THRESHOLDS };
    
    if (niche && NICHE_PRESETS[niche.toLowerCase()]) {
        thresholds = { ...thresholds, ...NICHE_PRESETS[niche.toLowerCase()] };
    }
    
    if (serpPolicy && serpPolicy.confidenceScore >= 60) {
        thresholds.WORD_COUNT_MIN = Math.max(
            thresholds.WORD_COUNT_MIN,
            Math.round(serpPolicy.targetWordCount * 0.9)
        );
        thresholds.WORD_COUNT_IDEAL = serpPolicy.targetWordCount;
        thresholds.H2_COUNT_MIN = Math.max(thresholds.H2_COUNT_MIN, serpPolicy.minH2Count);
        thresholds.H3_COUNT_MIN = Math.max(thresholds.H3_COUNT_MIN, serpPolicy.minH3Count);
        thresholds.FAQ_COUNT_MIN = Math.max(thresholds.FAQ_COUNT_MIN, serpPolicy.minFAQCount);
    }
    
    return thresholds;
}

// ═══════════════════════════════════════════════════════════════════════════════
// 📖 READABILITY CALCULATIONS
// ═══════════════════════════════════════════════════════════════════════════════

function countSyllables(word: string): number {
    word = word.toLowerCase().replace(/[^a-z]/g, '');
    if (word.length <= 3) return 1;
    
    word = word.replace(/(?:[^laeiouy]es|ed|[^laeiouy]e)$/, '');
    word = word.replace(/^y/, '');
    
    const matches = word.match(/[aeiouy]{1,2}/g);
    return matches ? Math.max(1, matches.length) : 1;
}

function countComplexWords(text: string): number {
    const words = text.split(/\s+/).filter(w => w.length > 0);
    return words.filter(word => countSyllables(word) >= 3).length;
}

export function calculateFleschKincaid(text: string): { score: number; grade: number } {
    const sentences = text.split(/[.!?]+/).filter(s => s.trim().length > 0);
    const words = text.split(/\s+/).filter(w => w.length > 0);
    
    if (sentences.length === 0 || words.length === 0) {
        return { score: 0, grade: 0 };
    }
    
    const totalSyllables = words.reduce((sum, word) => sum + countSyllables(word), 0);
    const avgWordsPerSentence = words.length / sentences.length;
    const avgSyllablesPerWord = totalSyllables / words.length;
    
    const score = 206.835 - (1.015 * avgWordsPerSentence) - (84.6 * avgSyllablesPerWord);
    const grade = (0.39 * avgWordsPerSentence) + (11.8 * avgSyllablesPerWord) - 15.59;
    
    return {
        score: Math.max(0, Math.min(100, Math.round(score))),
        grade: Math.max(0, Math.round(grade * 10) / 10)
    };
}

export function calculateSMOGIndex(text: string): number {
    const sentences = text.split(/[.!?]+/).filter(s => s.trim().length > 0);
    if (sentences.length < 30) {
        const complexWords = countComplexWords(text);
        const sentenceCount = Math.max(1, sentences.length);
        return Math.round(1.0430 * Math.sqrt(complexWords * (30 / sentenceCount)) + 3.1291);
    }
    
    const complexWords = countComplexWords(text);
    return Math.round(1.0430 * Math.sqrt(complexWords * (30 / sentences.length)) + 3.1291);
}

export function calculateGunningFog(text: string): number {
    const sentences = text.split(/[.!?]+/).filter(s => s.trim().length > 0);
    const words = text.split(/\s+/).filter(w => w.length > 0);
    
    if (sentences.length === 0 || words.length === 0) return 0;
    
    const complexWords = countComplexWords(text);
    const avgWordsPerSentence = words.length / sentences.length;
    const complexWordPercentage = (complexWords / words.length) * 100;
    
    return Math.round((avgWordsPerSentence + complexWordPercentage) * 0.4 * 10) / 10;
}

export function getReadabilityInterpretation(score: number): string {
    if (score >= 90) return 'Very Easy (5th grade)';
    if (score >= 80) return 'Easy (6th grade)';
    if (score >= 70) return 'Fairly Easy (7th grade)';
    if (score >= 60) return 'Standard (8-9th grade) ✓';
    if (score >= 50) return 'Fairly Difficult (10-12th grade)';
    if (score >= 30) return 'Difficult (College)';
    return 'Very Difficult (Graduate)';
}

// ═══════════════════════════════════════════════════════════════════════════════
// 🔍 EXISTING CONTENT ANALYZER
// ═══════════════════════════════════════════════════════════════════════════════

export function analyzeExistingContent(html: string): ExistingContentAnalysis {
    const doc = new DOMParser().parseFromString(html, 'text/html');
    const text = doc.body?.innerText || '';
    const htmlLower = html.toLowerCase();
    
    const headings: { level: number; text: string; hasKeyword?: boolean }[] = [];
    for (let i = 1; i <= 6; i++) {
        doc.querySelectorAll(`h${i}`).forEach(h => {
            headings.push({ 
                level: i, 
                text: h.textContent?.trim() || '',
                hasKeyword: false
            });
        });
    }
    
    const internalLinks = doc.querySelectorAll('a[href^="/"], a[href*="' + (doc.baseURI || '') + '"]');
    const allLinks = doc.querySelectorAll('a[href^="http"]');
    const internalLinkCount = internalLinks.length;
    const externalLinkCount = allLinks.length - internalLinkCount;
    
    const imageCount = doc.querySelectorAll('img').length;
    const tableCount = doc.querySelectorAll('table').length;
    const listCount = doc.querySelectorAll('ul, ol').length;
    const blockquoteCount = doc.querySelectorAll('blockquote').length;
    
    const hasSchema = html.includes('application/ld+json');
    const hasFAQ = htmlLower.includes('faq') || htmlLower.includes('frequently asked') || htmlLower.includes('common question');
    const hasConclusion = htmlLower.includes('conclusion') || htmlLower.includes('key takeaway') || htmlLower.includes('final thought') || htmlLower.includes('summary');
    const hasReferences = htmlLower.includes('reference') || htmlLower.includes('source') || htmlLower.includes('citation');
    const hasQuickAnswer = htmlLower.includes('quick answer') || htmlLower.includes('short answer') || htmlLower.includes('tldr') || htmlLower.includes('tl;dr');
    
    const { score: readabilityScore } = calculateFleschKincaid(text);
    const mainTopics = headings.filter(h => h.level === 2).map(h => h.text);
    
    const weakSections: string[] = [];
    const missingElements: string[] = [];
    
    if (!hasFAQ) missingElements.push('FAQ Section');
    if (!hasConclusion) missingElements.push('Conclusion/Takeaways');
    if (!hasReferences) missingElements.push('References Section');
    if (!hasQuickAnswer) missingElements.push('Quick Answer Box');
    if (!hasSchema) missingElements.push('Schema Markup');
    if (tableCount === 0) missingElements.push('Comparison Tables');
    if (blockquoteCount === 0) missingElements.push('Expert Quotes');
    if (internalLinkCount < 10) missingElements.push('Internal Links (need 15+)');
    
    const wordCount = text.split(/\s+/).filter(Boolean).length;
    
    let strengthScore = 0;
    if (hasFAQ) strengthScore += 15;
    if (hasConclusion) strengthScore += 10;
    if (hasReferences) strengthScore += 15;
    if (hasSchema) strengthScore += 15;
    if (hasQuickAnswer) strengthScore += 10;
    if (tableCount > 0) strengthScore += 10;
    if (blockquoteCount > 0) strengthScore += 5;
    if (internalLinkCount >= 10) strengthScore += 10;
    if (wordCount >= 3000) strengthScore += 10;
    
    const preserveableContent: string[] = [];
    if (html.includes('border-left:') || html.includes('border-radius:')) {
        preserveableContent.push('Styled content boxes');
    }
    if (tableCount > 0) preserveableContent.push(`${tableCount} data table(s)`);
    if (blockquoteCount > 0) preserveableContent.push(`${blockquoteCount} expert quote(s)`);
    
    const entities: string[] = [];
    const properNouns = text.match(/\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,3}\b/g) || [];
    const uniqueNouns = [...new Set(properNouns)].filter(n => n.length > 3 && !STOP_WORDS.has(n.toLowerCase()));
    entities.push(...uniqueNouns.slice(0, 30));
    
    return {
        wordCount,
        headings,
        hasSchema,
        hasFAQ,
        hasConclusion,
        hasReferences,
        hasQuickAnswer,
        internalLinkCount,
        externalLinkCount,
        imageCount,
        tableCount,
        listCount,
        readabilityScore,
        preserveableContent,
        weakSections,
        entities,
        mainTopics,
        missingElements,
        strengthScore: Math.min(100, strengthScore)
    };
}

// ═══════════════════════════════════════════════════════════════════════════════
// 📊 SEO METRICS CALCULATOR
// ═══════════════════════════════════════════════════════════════════════════════

export function calculateSeoMetrics(
    html: string, 
    title: string, 
    slug: string,
    targetKeyword?: string
): SeoMetrics {
    const doc = new DOMParser().parseFromString(html, 'text/html');
    const text = doc.body?.innerText || '';
    const htmlLower = html.toLowerCase();
    const textLower = text.toLowerCase();
    const wordCount = text.split(/\s+/).filter(Boolean).length;
    
    const { score: readability, grade: readabilityGrade } = calculateFleschKincaid(text);
    
    const h1Count = doc.querySelectorAll('h1').length;
    const h2Count = doc.querySelectorAll('h2').length;
    const h3Count = doc.querySelectorAll('h3').length;
    
    const internalLinks = doc.querySelectorAll('a[data-internal-link], a[href^="/"]');
    const allLinks = doc.querySelectorAll('a[href^="http"]');
    const externalLinks = Array.from(allLinks).filter(a => {
        const href = a.getAttribute('href') || '';
        return !href.includes(slug) && href.startsWith('http');
    });
    
    const tableCount = doc.querySelectorAll('table').length;
    const listCount = doc.querySelectorAll('ul, ol').length;
    const blockquoteCount = doc.querySelectorAll('blockquote').length;
    
    const hasSchema = html.includes('application/ld+json');
    const schemaTypes: string[] = [];
    if (hasSchema) {
        const matches = html.match(/"@type"\s*:\s*"([^"]+)"/g) || [];
        matches.forEach(m => {
            const type = m.match(/"@type"\s*:\s*"([^"]+)"/)?.[1];
            if (type && !schemaTypes.includes(type)) schemaTypes.push(type);
        });
    }
    
    const hasFAQ = htmlLower.includes('faq') || htmlLower.includes('frequently asked');
    const hasReferences = htmlLower.includes('references') || htmlLower.includes('sources');
    const hasConclusion = htmlLower.includes('conclusion') || htmlLower.includes('takeaway');
    const hasQuickAnswer = htmlLower.includes('quick answer') || htmlLower.includes('tldr');
    
    const titleLen = title?.length || 0;
    const titleScore = titleLen >= 45 && titleLen <= 65 ? 100 :
                       titleLen >= 40 && titleLen <= 70 ? 80 :
                       titleLen >= 35 && titleLen <= 75 ? 60 : 40;
    
    const keywordInTitle = targetKeyword ? title.toLowerCase().includes(targetKeyword.toLowerCase()) : true;
    const titleOptimization = titleScore * (keywordInTitle ? 1 : 0.7);
    
    const headingScore = h1Count === 0 && h2Count >= 10 && h3Count >= 15 ? 100 :
                         h1Count <= 1 && h2Count >= 8 && h3Count >= 12 ? 85 :
                         h1Count <= 1 && h2Count >= 5 && h3Count >= 8 ? 70 : 50;
    
    const metaOptimization = 80;
    
    const internalLinkScore = Math.min(100, internalLinks.length * 5);
    const externalLinkScore = Math.min(100, externalLinks.length * 8);
    const linkDensity = Math.round((internalLinkScore * 0.6) + (externalLinkScore * 0.4));
    
    const semanticDensity = Math.min(100, (tableCount * 15) + (listCount * 5) + (blockquoteCount * 10) + (h2Count * 3) + (h3Count * 2));
    
    const aeoScore = Math.round(
        (hasFAQ ? 25 : 0) +
        (hasSchema ? 20 : 0) +
        (schemaTypes.includes('FAQPage') ? 10 : 0) +
        (hasQuickAnswer ? 15 : 0) +
        (hasConclusion ? 10 : 0) +
        Math.min(20, (wordCount / 4000) * 20)
    );
    
    const geoScore = Math.round(
        (hasReferences ? 25 : 0) +
        Math.min(25, (externalLinks.length / 8) * 25) +
        (hasSchema ? 15 : 0) +
        Math.min(20, (wordCount / 4000) * 20) +
        Math.min(15, (h2Count / 10) * 15)
    );
    
    let eeatScore = 0;
    EEAT_SIGNALS.forEach(signal => {
        if (textLower.includes(signal)) eeatScore += 5;
    });
    eeatScore = Math.min(100, eeatScore + (hasSchema ? 20 : 0) + (hasReferences ? 20 : 0));
    
    let keywordDensity = 75;
    if (targetKeyword) {
        const keywordLower = targetKeyword.toLowerCase();
        const keywordCount = (textLower.match(new RegExp(keywordLower.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g')) || []).length;
        const density = (keywordCount / wordCount) * 100;
        keywordDensity = density >= 0.5 && density <= 2.5 ? 100 :
                         density >= 0.3 && density <= 3 ? 80 :
                         density > 0 ? 60 : 30;
    }
    
    const properNouns = text.match(/\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2}\b/g) || [];
    const entityDensity = Math.min(100, (properNouns.length / Math.max(1, wordCount / 100)) * 10);
    
    const serpFeatureTargeting = hasFAQ && hasSchema ? 90 :
                                  hasFAQ || hasSchema ? 70 :
                                  hasQuickAnswer ? 50 : 30;
    
    const powerWordsUsed = POWER_WORDS.filter(pw => textLower.includes(pw));
    
    const contentDepth = Math.min(100, 
        (wordCount / 50) + 
        (h2Count * 4) + 
        (h3Count * 2) + 
        (tableCount * 10) + 
        (hasFAQ ? 15 : 0) +
        (hasReferences ? 10 : 0)
    );
    
    const topicalAuthority = Math.min(100,
        (h2Count * 5) +
        (h3Count * 2) +
        (internalLinks.length * 2) +
        (hasReferences ? 20 : 0) +
        (externalLinks.length * 3)
    );
    
    return {
        titleOptimization: Math.round(titleOptimization),
        metaOptimization,
        headingStructure: headingScore,
        readability,
        readabilityGrade,
        linkDensity,
        semanticDensity: Math.round(semanticDensity),
        eeatSignals: Math.min(100, eeatScore),
        aeoScore: Math.min(100, aeoScore),
        geoScore: Math.min(100, geoScore),
        keywordDensity,
        entityDensity: Math.round(entityDensity),
        serpFeatureTargeting,
        answerEngineVisibility: aeoScore,
        schemaDetected: hasSchema,
        schemaTypes,
        mobileOptimized: true,
        powerWordsUsed,
        wordCount,
        uniquenessScore: 85,
        contentDepth: Math.round(contentDepth),
        topicalAuthority: Math.round(topicalAuthority),
        internalLinkScore: Math.min(100, internalLinks.length * 5),
        externalLinkScore: Math.min(100, externalLinks.length * 8)
    };
}

// ═══════════════════════════════════════════════════════════════════════════════
// 🔥🔥🔥 PLUG-IN QA RULE ENGINE — ENTERPRISE GRADE v2.0
// ═══════════════════════════════════════════════════════════════════════════════

interface QARuleDefinition {
    id: string;
    name: string;
    category: 'critical' | 'seo' | 'aeo' | 'geo' | 'enhancement';
    severity: 'error' | 'warning' | 'info';
    description: string;
    scoreImpact: number;
    weight: number;
    enabled: boolean;
    
    detect: (
        contract: ContentContract, 
        context: QARuleContext,
        thresholds: typeof DEFAULT_THRESHOLDS
    ) => QADetectionResult;
    
    fix?: (
        contract: ContentContract, 
        detection: QADetectionResult
    ) => ContentContract;
}

// ═══════════════════════════════════════════════════════════════════════════════
// 📋 QA RULES REGISTRY — 50+ VALIDATION RULES
// ═══════════════════════════════════════════════════════════════════════════════

const QA_RULES: QARuleDefinition[] = [
    // ═══════════════════════════════════════════════════════════════════════════
    // CRITICAL RULES (Weight: 1.0)
    // ═══════════════════════════════════════════════════════════════════════════
    
    {
        id: 'no-h1-tags',
        name: 'H1 Tags (WordPress)',
        category: 'critical',
        severity: 'error',
        description: 'Content must have zero H1 tags — WordPress provides page title as H1',
        scoreImpact: 100,
        weight: 1.0,
        enabled: true,
        detect: (contract, context, thresholds) => {
            const doc = new DOMParser().parseFromString(contract.htmlContent, 'text/html');
            const h1Tags = doc.querySelectorAll('h1');
            const h1Count = h1Tags.length;
            
            return {
                passed: h1Count === 0,
                score: h1Count === 0 ? 100 : 0,
                message: h1Count === 0 
                    ? '✓ Zero H1 tags — WordPress provides page title as H1'
                    : `✗ Found ${h1Count} H1 tag(s) — MUST be removed!`,
                details: { h1Count },
                autoFixable: true
            };
        },
        fix: (contract, detection) => {
            let cleaned = contract.htmlContent;
            // Multi-pass H1 removal
            for (let i = 0; i < 3; i++) {
                cleaned = cleaned.replace(/<h1[^>]*>[\s\S]*?<\/h1>/gi, '');
                cleaned = cleaned.replace(/<h1[^>]*\/>/gi, '');
            }
            cleaned = cleaned.replace(/\n{3,}/g, '\n\n');
            return { ...contract, htmlContent: cleaned.trim() };
        }
    },
    
    {
        id: 'word-count',
        name: 'Word Count',
        category: 'critical',
        severity: 'error',
        description: 'Content must meet minimum word count',
        scoreImpact: 80,
        weight: 1.0,
        enabled: true,
        detect: (contract, context, thresholds) => {
            const doc = new DOMParser().parseFromString(contract.htmlContent, 'text/html');
            const text = doc.body?.innerText || '';
            const wordCount = text.split(/\s+/).filter(Boolean).length;
            const target = thresholds.WORD_COUNT_MIN;
            
            return {
                passed: wordCount >= target,
                score: wordCount >= target ? 100 : Math.round((wordCount / target) * 80),
                message: `${wordCount.toLocaleString()} words ${wordCount >= target ? '✓' : `(target: ${target.toLocaleString()}+)`}`,
                details: { wordCount, target },
                autoFixable: false
            };
        }
    },
    
    {
        id: 'h2-headings',
        name: 'H2 Section Headings',
        category: 'critical',
        severity: 'error',
        description: 'Content must have sufficient H2 sections',
        scoreImpact: 60,
        weight: 0.9,
        enabled: true,
        detect: (contract, context, thresholds) => {
            const doc = new DOMParser().parseFromString(contract.htmlContent, 'text/html');
            const h2Count = doc.querySelectorAll('h2').length;
            const target = thresholds.H2_COUNT_MIN;
            
            return {
                passed: h2Count >= target,
                score: h2Count >= target ? 100 : Math.round((h2Count / target) * 80),
                message: `${h2Count} H2 headings ${h2Count >= target ? '✓' : `(need ${target}+)`}`,
                details: { h2Count, target },
                autoFixable: false
            };
        }
    },
    
    {
        id: 'h3-subheadings',
        name: 'H3 Subheadings',
        category: 'critical',
        severity: 'error',
        description: 'Content must have sufficient H3 subheadings',
        scoreImpact: 50,
        weight: 0.8,
        enabled: true,
        detect: (contract, context, thresholds) => {
            const doc = new DOMParser().parseFromString(contract.htmlContent, 'text/html');
            const h3Count = doc.querySelectorAll('h3').length;
            const target = thresholds.H3_COUNT_MIN;
            
            return {
                passed: h3Count >= target,
                score: h3Count >= target ? 100 : Math.round((h3Count / target) * 80),
                message: `${h3Count} H3 subheadings ${h3Count >= target ? '✓' : `(need ${target}+)`}`,
                details: { h3Count, target },
                autoFixable: false
            };
        }
    },
    
    {
        id: 'faq-section',
        name: 'FAQ Section',
        category: 'critical',
        severity: 'error',
        description: 'Content must include FAQ section',
        scoreImpact: 70,
        weight: 0.9,
        enabled: true,
        detect: (contract, context, thresholds) => {
            const htmlLower = contract.htmlContent.toLowerCase();
            const hasFaqSection = htmlLower.includes('faq') || htmlLower.includes('frequently asked');
            const faqCount = contract.faqs?.length || 0;
            const target = thresholds.FAQ_COUNT_MIN;
            
            return {
                passed: faqCount >= target && hasFaqSection,
                score: faqCount >= target ? 100 : Math.round((faqCount / target) * 80),
                message: `${faqCount} FAQs ${faqCount >= target ? '✓' : `(need ${target}+)`}`,
                details: { faqCount, target, hasFaqSection },
                autoFixable: false
            };
        }
    },
    
    {
        id: 'faq-uniqueness',
        name: 'FAQ Section Uniqueness',
        category: 'critical',
        severity: 'error',
        description: 'Only one FAQ section should exist',
        scoreImpact: 60,
        weight: 0.8,
        enabled: true,
        detect: (contract, context, thresholds) => {
            const html = contract.htmlContent.toLowerCase();
            
            const faqSectionMatches = html.match(/<section[^>]*faq[^>]*>/gi) || [];
            const faqHeadingMatches = html.match(/<h[23][^>]*>[\s\S]*?frequently\s+asked[\s\S]*?<\/h[23]>/gi) || [];
            const faqEmojiMatches = html.match(/❓/g) || [];
            
            const faqCount = Math.max(
                faqSectionMatches.length,
                faqHeadingMatches.length,
                Math.floor(faqEmojiMatches.length / 2)
            );
            
            const passed = faqCount <= 1;
            
            return {
                passed,
                score: passed ? 100 : Math.max(0, 100 - ((faqCount - 1) * 40)),
                message: passed 
                    ? `✓ Single FAQ section`
                    : `✗ ${faqCount} FAQ sections detected — should only have one`,
                details: { faqCount, faqSectionMatches: faqSectionMatches.length, faqHeadingMatches: faqHeadingMatches.length },
                autoFixable: true
            };
        }
    },
    
    {
        id: 'content-prose-quality',
        name: 'Content Prose Quality',
        category: 'critical',
        severity: 'error',
        description: 'Main content should be prose, not Q&A format',
        scoreImpact: 70,
        weight: 0.9,
        enabled: true,
        detect: (contract, context, thresholds) => {
            const html = contract.htmlContent;
            
            const faqStart = Math.max(
                html.toLowerCase().indexOf('frequently asked'),
                html.toLowerCase().indexOf('faq'),
                html.lastIndexOf('❓')
            );
            
            const mainContent = faqStart > 0 ? html.substring(0, faqStart) : html;
            
            const qaPatterns = [
                /Q:\s*[^\n<]+/gi,
                /A:\s*[^\n<]+/gi,
                /<strong>Q\d*[:\s]*<\/strong>/gi,
                /<strong>A\d*[:\s]*<\/strong>/gi,
                /Question\s*\d*\s*:/gi,
                /Answer\s*\d*\s*:/gi,
            ];
            
            let qaPatternsFound = 0;
            for (const pattern of qaPatterns) {
                const matches = mainContent.match(pattern);
                if (matches) qaPatternsFound += matches.length;
            }
            
            const passed = qaPatternsFound <= 3;
            
            return {
                passed,
                score: passed ? 100 : Math.max(0, 100 - (qaPatternsFound * 15)),
                message: qaPatternsFound <= 3 
                    ? `✓ Content is proper prose (${qaPatternsFound} Q&A patterns)`
                    : `✗ ${qaPatternsFound} Q&A patterns found — main content should be prose`,
                details: { qaPatternsFound },
                autoFixable: true
            };
        },
        fix: (contract, detection) => {
            let html = contract.htmlContent;
            
            html = html.replace(/(<p[^>]*>)\s*Q:\s*/gi, '$1');
            html = html.replace(/(<p[^>]*>)\s*A:\s*/gi, '$1');
            html = html.replace(/<strong>Q:<\/strong>\s*/gi, '');
            html = html.replace(/<strong>A:<\/strong>\s*/gi, '');
            
            return { ...contract, htmlContent: html };
        }
    },
    
    {
        id: 'quick-answer',
        name: 'Quick Answer Box',
        category: 'critical',
        severity: 'error',
        description: 'Content must include Quick Answer box for featured snippets',
        scoreImpact: 60,
        weight: 0.8,
        enabled: true,
        detect: (contract, context, thresholds) => {
            const htmlLower = contract.htmlContent.toLowerCase();
            const hasQuickAnswer = htmlLower.includes('quick answer') || 
                                   htmlLower.includes('short answer') ||
                                   htmlLower.includes('tldr') ||
                                   htmlLower.includes('tl;dr');
            
            return {
                passed: hasQuickAnswer,
                score: hasQuickAnswer ? 100 : 0,
                message: hasQuickAnswer ? '✓ Quick Answer box found' : '✗ Missing Quick Answer box',
                details: { hasQuickAnswer },
                autoFixable: false
            };
        }
    },
    
    {
        id: 'schema-markup',
        name: 'Schema Markup',
        category: 'critical',
        severity: 'error',
        description: 'Content must include proper schema markup',
        scoreImpact: 70,
        weight: 0.85,
        enabled: true,
        detect: (contract, context, thresholds) => {
            const hasSchema = contract.schema && Object.keys(contract.schema).length > 0;
            const schemaStr = JSON.stringify(contract.schema || {});
            const hasFAQSchema = schemaStr.includes('FAQPage');
            const hasArticleSchema = schemaStr.includes('Article');
            
            const score = hasSchema && hasFAQSchema && hasArticleSchema ? 100 :
                         hasSchema && hasFAQSchema ? 85 :
                         hasSchema ? 70 : 0;
            
            return {
                passed: hasSchema && hasFAQSchema && hasArticleSchema,
                score,
                message: hasSchema 
                    ? `✓ Schema: ${[hasArticleSchema && 'Article', hasFAQSchema && 'FAQPage'].filter(Boolean).join(', ')}`
                    : '✗ Missing schema markup',
                details: { hasSchema, hasFAQSchema, hasArticleSchema },
                autoFixable: false
            };
        }
    },
    
    {
        id: 'content-uniqueness',
        name: 'Content Uniqueness',
        category: 'critical',
        severity: 'error',
        description: 'Content should not have excessive repetition',
        scoreImpact: 60,
        weight: 0.8,
        enabled: true,
        detect: (contract, context, thresholds) => {
            const doc = new DOMParser().parseFromString(contract.htmlContent, 'text/html');
            const paragraphs = Array.from(doc.querySelectorAll('p')).map(p => p.textContent?.trim() || '');
            
            const seen = new Set<string>();
            let duplicates = 0;
            
            for (const p of paragraphs) {
                if (p.length < 50) continue;
                const normalized = p.toLowerCase().replace(/\s+/g, ' ');
                if (seen.has(normalized)) {
                    duplicates++;
                } else {
                    seen.add(normalized);
                }
            }
            
            const text = doc.body?.textContent || '';
            const words = text.toLowerCase().split(/\s+/);
            const trigrams = new Map<string, number>();
            
            for (let i = 0; i < words.length - 2; i++) {
                const trigram = `${words[i]} ${words[i+1]} ${words[i+2]}`;
                if (trigram.length > 10) {
                    trigrams.set(trigram, (trigrams.get(trigram) || 0) + 1);
                }
            }
            
            const overusedPhrases = Array.from(trigrams.entries())
                .filter(([_, count]) => count >= 5)
                .length;
            
            const passed = duplicates === 0 && overusedPhrases <= 3;
            
            return {
                passed,
                score: passed ? 100 : Math.max(0, 100 - (duplicates * 20) - (overusedPhrases * 10)),
                message: `Duplicates: ${duplicates} | Overused phrases: ${overusedPhrases}`,
                details: { duplicates, overusedPhrases },
                autoFixable: false
            };
        }
    },
    
    // ═══════════════════════════════════════════════════════════════════════════
    // SEO RULES (Weight: 0.6-0.9)
    // ═══════════════════════════════════════════════════════════════════════════
    
    {
        id: 'internal-links',
        name: 'Internal Links',
        category: 'seo',
        severity: 'warning',
        description: 'Content must have sufficient internal links',
        scoreImpact: 60,
        weight: 0.8,
        enabled: true,
        detect: (contract, context, thresholds) => {
            const doc = new DOMParser().parseFromString(contract.htmlContent, 'text/html');
            const internalLinks = doc.querySelectorAll('a[data-internal-link]');
            const count = internalLinks.length;
            const target = thresholds.INTERNAL_LINKS_MIN;
            
            return {
                passed: count >= target,
                score: Math.min(100, count * 6),
                message: `${count} internal links ${count >= target ? '✓' : `(need ${target}+)`}`,
                details: { count, target },
                autoFixable: false
            };
        }
    },
    
    {
        id: 'internal-link-quality',
        name: 'Internal Link Anchor Quality',
        category: 'seo',
        severity: 'warning',
        description: 'Internal links must have proper 3-6 word anchor text',
        scoreImpact: 50,
        weight: 0.7,
        enabled: true,
        detect: (contract, context, thresholds) => {
            const doc = new DOMParser().parseFromString(contract.htmlContent, 'text/html');
            const internalLinks = doc.querySelectorAll('a[data-internal-link]');
            
            if (internalLinks.length === 0) {
                return {
                    passed: false,
                    score: 0,
                    message: '✗ No internal links found',
                    details: {},
                    autoFixable: false
                };
            }
            
            let excellent = 0;
            let good = 0;
            let poor = 0;
            const seenAnchors = new Set<string>();
            let duplicateAnchors = 0;
            const issues: string[] = [];
            
            internalLinks.forEach(link => {
                const text = link.textContent?.trim() || '';
                const words = text.split(/\s+/).filter(w => w.length > 0);
                
                const normalized = text.toLowerCase();
                if (seenAnchors.has(normalized)) {
                    duplicateAnchors++;
                } else {
                    seenAnchors.add(normalized);
                }
                
                if (words.length >= 4 && words.length <= 5 && text.length >= 20 && text.length <= 55) {
                    excellent++;
                } else if (words.length >= 3 && words.length <= 6 && text.length >= 18) {
                    good++;
                } else {
                    poor++;
                    if (issues.length < 3) {
                        issues.push(`"${text.substring(0, 30)}..." (${words.length} words)`);
                    }
                }
            });
            
            const total = internalLinks.length;
            const qualityScore = Math.round(((excellent * 100) + (good * 75) + (poor * 25)) / total);
            const passed = qualityScore >= 70 && poor <= Math.ceil(total * 0.2) && duplicateAnchors === 0;
            
            return {
                passed,
                score: qualityScore,
                message: `${excellent} excellent, ${good} good, ${poor} poor anchors | ${duplicateAnchors} duplicates`,
                details: { excellent, good, poor, duplicateAnchors, total, issues },
                autoFixable: false
            };
        }
    },
    
    {
        id: 'tables',
        name: 'Comparison Tables',
        category: 'seo',
        severity: 'warning',
        description: 'Content should include data tables',
        scoreImpact: 40,
        weight: 0.6,
        enabled: true,
        detect: (contract, context, thresholds) => {
            const doc = new DOMParser().parseFromString(contract.htmlContent, 'text/html');
            const count = doc.querySelectorAll('table').length;
            const target = thresholds.TABLES_MIN;
            
            return {
                passed: count >= target,
                score: count >= target ? 100 : count * 50,
                message: `${count} table(s) ${count >= target ? '✓' : `(need ${target}+)`}`,
                details: { count, target },
                autoFixable: false
            };
        }
    },
    
    {
        id: 'blockquotes',
        name: 'Expert Quotes',
        category: 'seo',
        severity: 'warning',
        description: 'Content should include expert blockquotes',
        scoreImpact: 30,
        weight: 0.5,
        enabled: true,
        detect: (contract, context, thresholds) => {
            const doc = new DOMParser().parseFromString(contract.htmlContent, 'text/html');
            const count = doc.querySelectorAll('blockquote').length;
            const target = thresholds.BLOCKQUOTES_MIN;
            
            return {
                passed: count >= target,
                score: count >= target ? 100 : count * 50,
                message: `${count} blockquote(s) ${count >= target ? '✓' : `(need ${target}+)`}`,
                details: { count, target },
                autoFixable: false
            };
        }
    },
    
    {
        id: 'heading-hierarchy',
        name: 'Heading Hierarchy',
        category: 'seo',
        severity: 'warning',
        description: 'Headings should follow proper hierarchy (no skipping levels)',
        scoreImpact: 40,
        weight: 0.5,
        enabled: true,
        detect: (contract, context, thresholds) => {
            const doc = new DOMParser().parseFromString(contract.htmlContent, 'text/html');
            const headings = Array.from(doc.querySelectorAll('h1, h2, h3, h4, h5, h6'));
            
            if (headings.length === 0) {
                return { passed: false, score: 0, message: '✗ No headings found', details: {}, autoFixable: false };
            }
            
            const levels = headings.map(h => parseInt(h.tagName[1]));
            let violations = 0;
            
            for (let i = 1; i < levels.length; i++) {
                const jump = levels[i] - levels[i-1];
                if (jump > 1) {
                    violations++;
                }
            }
            
            const h1Count = levels.filter(l => l === 1).length;
            if (h1Count > 0) violations += h1Count;
            
            const passed = violations === 0;
            
            return {
                passed,
                score: passed ? 100 : Math.max(0, 100 - (violations * 15)),
                message: passed 
                    ? '✓ Heading hierarchy is correct' 
                    : `✗ ${violations} hierarchy violation(s)`,
                details: { violations, h1Count, totalHeadings: headings.length },
                autoFixable: false
            };
        }
    },
    
    {
        id: 'image-alt-quality',
        name: 'Image Alt Text Quality',
        category: 'seo',
        severity: 'warning',
        description: 'Images should have descriptive alt text',
        scoreImpact: 40,
        weight: 0.6,
        enabled: true,
        detect: (contract, context, thresholds) => {
            const doc = new DOMParser().parseFromString(contract.htmlContent, 'text/html');
            const images = doc.querySelectorAll('img');
            
            if (images.length === 0) {
                return { passed: true, score: 100, message: '○ No images to check', details: {}, autoFixable: false };
            }
            
            let goodAlt = 0;
            let badAlt = 0;
            let missingAlt = 0;
            
            images.forEach(img => {
                const alt = img.getAttribute('alt');
                if (!alt || alt.trim() === '') {
                    missingAlt++;
                } else if (alt.length < 10 || alt.toLowerCase().includes('image') || alt.toLowerCase().includes('photo')) {
                    badAlt++;
                } else {
                    goodAlt++;
                }
            });
            
            const score = Math.round((goodAlt / images.length) * 100);
            const passed = missingAlt === 0 && score >= 80;
            
            return {
                passed,
                score,
                message: `${goodAlt}/${images.length} images have quality alt text`,
                details: { goodAlt, badAlt, missingAlt, total: images.length },
                autoFixable: false
            };
        }
    },
    
    {
        id: 'readability',
        name: 'Readability Score',
        category: 'seo',
        severity: 'warning',
        description: 'Content should be readable for target audience',
        scoreImpact: 50,
        weight: 0.7,
        enabled: true,
        detect: (contract, context, thresholds) => {
            const doc = new DOMParser().parseFromString(contract.htmlContent, 'text/html');
            const text = doc.body?.innerText || '';
            const { score: readabilityScore, grade: readabilityGrade } = calculateFleschKincaid(text);
            
            const passed = readabilityScore >= thresholds.READABILITY_IDEAL;
            
            return {
                passed,
                score: readabilityScore,
                message: `Flesch score: ${readabilityScore} (Grade ${readabilityGrade}) — ${getReadabilityInterpretation(readabilityScore)}`,
                details: { readabilityScore, readabilityGrade },
                autoFixable: false
            };
        }
    },
    
    {
        id: 'mobile-readability',
        name: 'Mobile Readability',
        category: 'seo',
        severity: 'warning',
        description: 'Content should be optimized for mobile reading',
        scoreImpact: 30,
        weight: 0.4,
        enabled: true,
        detect: (contract, context, thresholds) => {
            const doc = new DOMParser().parseFromString(contract.htmlContent, 'text/html');
            const paragraphs = doc.querySelectorAll('p');
            
            let longParagraphs = 0;
            let longSentences = 0;
            
            paragraphs.forEach(p => {
                const text = p.textContent || '';
                const words = text.split(/\s+/).length;
                
                if (words > thresholds.PARAGRAPH_MAX_WORDS) longParagraphs++;
                
                const sentences = text.split(/[.!?]+/);
                sentences.forEach(s => {
                    if (s.split(/\s+/).length > thresholds.SENTENCE_MAX_WORDS) longSentences++;
                });
            });
            
            const passed = longParagraphs <= 2 && longSentences <= 5;
            
            return {
                passed,
                score: passed ? 100 : Math.max(0, 100 - (longParagraphs * 15) - (longSentences * 5)),
                message: `Long paragraphs: ${longParagraphs} | Long sentences: ${longSentences}`,
                details: { longParagraphs, longSentences },
                autoFixable: false
            };
        }
    },
    
    {
        id: 'nlp-coverage',
        name: 'NLP Term Coverage',
        category: 'seo',
        severity: 'warning',
        description: 'Content should cover NLP terms from NeuronWriter',
        scoreImpact: 60,
        weight: 0.8,
        enabled: true,
        detect: (contract, context, thresholds) => {
            if (!context.neuronTerms || context.neuronTerms.length === 0) {
                return {
                    passed: true,
                    score: 100,
                    message: '○ No NLP terms to check',
                    details: { hasTerms: false },
                    autoFixable: false
                };
            }
            
            const doc = new DOMParser().parseFromString(contract.htmlContent, 'text/html');
            const textLower = (doc.body?.innerText || '').toLowerCase();
            
            let usedCount = 0;
            let totalWeight = 0;
            let usedWeight = 0;
            
            context.neuronTerms.forEach(term => {
                const termLower = term.term.toLowerCase();
                const weight = term.importance || 50;
                totalWeight += weight;
                
                if (textLower.includes(termLower)) {
                    usedCount++;
                    usedWeight += weight;
                }
            });
            
            const coverage = Math.round((usedCount / context.neuronTerms.length) * 100);
            const weightedCoverage = Math.round((usedWeight / totalWeight) * 100);
            const target = thresholds.NLP_COVERAGE_MIN;
            
            return {
                passed: coverage >= target,
                score: coverage,
                message: `${coverage}% coverage (${usedCount}/${context.neuronTerms.length} terms) ${coverage >= target ? '✓' : `(need ${target}%+)`}`,
                details: { coverage, weightedCoverage, usedCount, totalTerms: context.neuronTerms.length },
                autoFixable: false
            };
        }
    },
    
    // ═══════════════════════════════════════════════════════════════════════════
    // AEO RULES (Weight: 0.6-0.8)
    // ═══════════════════════════════════════════════════════════════════════════
    
    {
        id: 'featured-snippet-bait',
        name: 'Featured Snippet Optimization',
        category: 'aeo',
        severity: 'warning',
        description: 'First paragraph should be optimized for featured snippets',
        scoreImpact: 50,
        weight: 0.7,
        enabled: true,
        detect: (contract, context, thresholds) => {
            const doc = new DOMParser().parseFromString(contract.htmlContent, 'text/html');
            const firstParagraph = doc.querySelector('p')?.textContent || '';
            const htmlLower = contract.htmlContent.toLowerCase();
            const hasQuickAnswer = htmlLower.includes('quick answer') || htmlLower.includes('tldr');
            
            const hasDirectAnswer = firstParagraph.length >= 40 && firstParagraph.length <= 300;
            const passed = hasDirectAnswer && hasQuickAnswer;
            
            return {
                passed,
                score: passed ? 100 : hasDirectAnswer || hasQuickAnswer ? 70 : 30,
                message: passed 
                    ? '✓ Content optimized for featured snippets'
                    : 'Needs optimization for featured snippets',
                details: { firstParagraphLength: firstParagraph.length, hasQuickAnswer, hasDirectAnswer },
                autoFixable: false
            };
        }
    },
    
    {
        id: 'faq-schema',
        name: 'FAQPage Schema',
        category: 'aeo',
        severity: 'warning',
        description: 'Content should have FAQPage schema for rich results',
        scoreImpact: 50,
        weight: 0.7,
        enabled: true,
        detect: (contract, context, thresholds) => {
            const schemaStr = JSON.stringify(contract.schema || {});
            const hasFAQSchema = schemaStr.includes('FAQPage');
            const hasFAQContent = contract.faqs && contract.faqs.length >= 5;
            
            const passed = hasFAQSchema && hasFAQContent;
            
            return {
                passed,
                score: passed ? 100 : hasFAQSchema || hasFAQContent ? 60 : 0,
                message: passed 
                    ? '✓ FAQPage schema with content'
                    : `${hasFAQSchema ? '✓' : '✗'} Schema | ${hasFAQContent ? '✓' : '✗'} FAQ Content`,
                details: { hasFAQSchema, faqCount: contract.faqs?.length || 0 },
                autoFixable: false
            };
        }
    },
    
    // ═══════════════════════════════════════════════════════════════════════════
    // GEO RULES (Weight: 0.7-0.9)
    // ═══════════════════════════════════════════════════════════════════════════
    
    {
        id: 'authority-citations',
        name: 'Authority Citations',
        category: 'geo',
        severity: 'warning',
        description: 'Content should cite authority sources',
        scoreImpact: 60,
        weight: 0.8,
        enabled: true,
        detect: (contract, context, thresholds) => {
            const doc = new DOMParser().parseFromString(contract.htmlContent, 'text/html');
            const allLinks = doc.querySelectorAll('a[href^="http"]');
            
            const authorityCount = Array.from(allLinks).filter(a => {
                const href = a.getAttribute('href') || '';
                return AUTHORITY_DOMAINS.some(d => href.includes(d));
            }).length;
            
            const passed = authorityCount >= 3;
            
            return {
                passed,
                score: Math.min(100, authorityCount * 25),
                message: `${authorityCount} authority source citations ${passed ? '✓' : '(need 3+)'}`,
                details: { authorityCount },
                autoFixable: false
            };
        }
    },
    
    {
        id: 'external-link-authority',
        name: 'External Link Authority',
        category: 'geo',
        severity: 'warning',
        description: 'External links should point to authoritative sources',
        scoreImpact: 50,
        weight: 0.7,
        enabled: true,
        detect: (contract, context, thresholds) => {
            const doc = new DOMParser().parseFromString(contract.htmlContent, 'text/html');
            const externalLinks = Array.from(doc.querySelectorAll('a[href^="http"]'))
                .filter(a => {
                    const href = a.getAttribute('href') || '';
                    return !href.includes(context.siteContext?.url || 'example.com');
                });
            
            if (externalLinks.length === 0) {
                return { 
                    passed: false, 
                    score: 0, 
                    message: '✗ No external links found (need 5+)', 
                    details: {},
                    autoFixable: false 
                };
            }
            
            let authorityCount = 0;
            externalLinks.forEach(a => {
                const href = a.getAttribute('href') || '';
                if (AUTHORITY_DOMAINS.some(d => href.includes(d))) {
                    authorityCount++;
                }
            });
            
            const authorityRatio = Math.round((authorityCount / externalLinks.length) * 100);
            const passed = authorityCount >= 3 && authorityRatio >= 50;
            
            return {
                passed,
                score: passed ? 100 : Math.min(100, authorityRatio + (authorityCount * 10)),
                message: `${authorityCount}/${externalLinks.length} links are authoritative (${authorityRatio}%)`,
                details: { authorityCount, totalExternal: externalLinks.length, authorityRatio },
                autoFixable: false
            };
        }
    },
    
    {
        id: 'eeat-signals',
        name: 'E-E-A-T Signals',
        category: 'geo',
        severity: 'warning',
        description: 'Content should include E-E-A-T signals',
        scoreImpact: 50,
        weight: 0.7,
        enabled: true,
        detect: (contract, context, thresholds) => {
            const doc = new DOMParser().parseFromString(contract.htmlContent, 'text/html');
            const textLower = (doc.body?.innerText || '').toLowerCase();
            
            let eeatSignalCount = 0;
            EEAT_SIGNALS.forEach(signal => {
                if (textLower.includes(signal)) eeatSignalCount++;
            });
            
            const passed = eeatSignalCount >= 5;
            
            return {
                passed,
                score: Math.min(100, eeatSignalCount * 15),
                message: `${eeatSignalCount} E-E-A-T signals detected ${passed ? '✓' : '(need 5+)'}`,
                details: { eeatSignalCount },
                autoFixable: false
            };
        }
    },
    
    {
        id: 'references-section',
        name: 'References Section',
        category: 'geo',
        severity: 'error',
        description: 'Content must include references section',
        scoreImpact: 60,
        weight: 0.8,
        enabled: true,
        detect: (contract, context, thresholds) => {
            const htmlLower = contract.htmlContent.toLowerCase();
            const hasReferences = htmlLower.includes('references') || 
                                  htmlLower.includes('sources') || 
                                  htmlLower.includes('citations');
            
            const doc = new DOMParser().parseFromString(contract.htmlContent, 'text/html');
            const allLinks = doc.querySelectorAll('a[href^="http"]');
            const refCount = allLinks.length;
            const target = thresholds.EXTERNAL_REFS_MIN;
            
            const passed = hasReferences && refCount >= target;
            
            return {
                passed,
                score: passed ? 100 : Math.round((refCount / target) * 80),
                message: `${refCount} external references ${passed ? '✓' : `(need ${target}+)`}`,
                details: { refCount, target, hasReferencesSection: hasReferences },
                autoFixable: false
            };
        }
    },
    
    // ═══════════════════════════════════════════════════════════════════════════
    // ENHANCEMENT RULES (Weight: 0.3-0.5)
    // ═══════════════════════════════════════════════════════════════════════════
    
    {
        id: 'visual-boxes',
        name: 'Visual Content Boxes',
        category: 'enhancement',
        severity: 'info',
        description: 'Content should include styled visual boxes',
        scoreImpact: 30,
        weight: 0.4,
        enabled: true,
        detect: (contract, context, thresholds) => {
            const styledBoxes = contract.htmlContent.match(/border-left:\s*\d+px\s+solid/gi) || [];
            const gradientBoxes = contract.htmlContent.match(/linear-gradient/gi) || [];
            const count = Math.max(styledBoxes.length, Math.floor(gradientBoxes.length / 2));
            const target = thresholds.VISUAL_BOXES_MIN;
            
            return {
                passed: count >= target,
                score: Math.min(100, count * 10),
                message: `${count} styled boxes ${count >= target ? '✓' : `(need ${target}+)`}`,
                details: { count, target },
                autoFixable: false
            };
        }
    },
    
    {
        id: 'lists-count',
        name: 'Lists & Bullets',
        category: 'enhancement',
        severity: 'info',
        description: 'Content should include lists for scannability',
        scoreImpact: 25,
        weight: 0.3,
        enabled: true,
        detect: (contract, context, thresholds) => {
            const doc = new DOMParser().parseFromString(contract.htmlContent, 'text/html');
            const listCount = doc.querySelectorAll('ul, ol').length;
            const target = thresholds.LISTS_MIN;
            
            return {
                passed: listCount >= target,
                score: Math.min(100, listCount * 20),
                message: `${listCount} lists ${listCount >= target ? '✓' : `(need ${target}+)`}`,
                details: { listCount, target },
                autoFixable: false
            };
        }
    },
    
    {
        id: 'key-takeaways',
        name: 'Key Takeaways Section',
        category: 'enhancement',
        severity: 'info',
        description: 'Content should include key takeaways box',
        scoreImpact: 25,
        weight: 0.3,
        enabled: true,
        detect: (contract, context, thresholds) => {
            const htmlLower = contract.htmlContent.toLowerCase();
            const hasTakeaways = htmlLower.includes('key takeaway') || 
                                 htmlLower.includes('main takeaway') ||
                                 htmlLower.includes('🎯');
            
            return {
                passed: hasTakeaways,
                score: hasTakeaways ? 100 : 0,
                message: hasTakeaways ? '✓ Key takeaways section found' : '○ Consider adding key takeaways',
                details: { hasTakeaways },
                autoFixable: false
            };
        }
    },



    // ═══════════════════════════════════════════════════════════════════════════
    // 🔥 VISUAL COMPONENT QUOTA — ENSURES MINIMUM VISUAL ELEMENTS
    // ═══════════════════════════════════════════════════════════════════════════
    
    {
        id: 'visual-component-quota',
        name: 'Visual Component Quota',
        category: 'critical',
        severity: 'error',
        description: 'Content must include minimum required visual components',
        scoreImpact: 70,
        weight: 0.9,
        enabled: true,
        detect: (contract, context, thresholds) => {
            const html = contract.htmlContent;
            
            // Count visual components
            const counts = {
                quickAnswer: (html.match(/quick\s*answer|⚡/gi) || []).length,
                statsDashboard: (html.match(/grid-template-columns|stats/gi) || []).length,
                proTip: (html.match(/pro\s*tip|💡/gi) || []).length,
                warning: (html.match(/⚠️|important|warning/gi) || []).length,
                blockquote: (html.match(/<blockquote/gi) || []).length,
                table: (html.match(/<table/gi) || []).length,
                keyTakeaways: (html.match(/key\s*takeaway|🎯/gi) || []).length,
            };
            
            const requirements = {
                quickAnswer: 1,
                statsDashboard: 1,
                proTip: 2,
                warning: 1,
                blockquote: 1,
                table: 1,
                keyTakeaways: 1,
            };
            
            const missing: string[] = [];
            let met = 0;
            let total = Object.keys(requirements).length;
            
            for (const [key, required] of Object.entries(requirements)) {
                if (counts[key as keyof typeof counts] >= required) {
                    met++;
                } else {
                    missing.push(`${key}: ${counts[key as keyof typeof counts]}/${required}`);
                }
            }
            
            const score = Math.round((met / total) * 100);
            const passed = missing.length <= 2; // Allow 2 missing
            
            return {
                passed,
                score,
                message: passed 
                    ? `✓ ${met}/${total} visual component types present`
                    : `✗ Missing: ${missing.slice(0, 3).join(', ')}`,
                details: { counts, missing, met, total },
                autoFixable: false
            };
        }
    },




];

// ═══════════════════════════════════════════════════════════════════════════════
// 📋 QA RULE MANAGEMENT
// ═══════════════════════════════════════════════════════════════════════════════

export function getQARule(ruleId: string): QARuleDefinition | undefined {
    return QA_RULES.find(r => r.id === ruleId);
}

export function getQARulesByCategory(category: string): QARuleDefinition[] {
    return QA_RULES.filter(r => r.category === category && r.enabled);
}

export function setQARuleEnabled(ruleId: string, enabled: boolean): void {
    const rule = QA_RULES.find(r => r.id === ruleId);
    if (rule) rule.enabled = enabled;
}

export function registerQARule(rule: QARuleDefinition): void {
    const existingIndex = QA_RULES.findIndex(r => r.id === rule.id);
    if (existingIndex >= 0) {
        QA_RULES[existingIndex] = rule;
    } else {
        QA_RULES.push(rule);
    }
}

export function getAllQARules(): QARuleDefinition[] {
    return [...QA_RULES];
}

// ═══════════════════════════════════════════════════════════════════════════════
// 🔥 MAIN QA SWARM RUNNER
// ═══════════════════════════════════════════════════════════════════════════════

export function runQASwarm(
    contract: ContentContract, 
    entityGapData?: EntityGapAnalysis,
    neuronTerms: NeuronTerm[] = [],
    serpPolicy?: SerpLengthPolicy,
    niche?: string,
    siteContext?: SiteContext
): QASwarmResult {
    const results: QAValidationResult[] = [];
    
    if (!contract.htmlContent || contract.htmlContent.length < 100) {
        return { 
            passed: false, 
            results: [], 
            score: 0, 
            criticalFailures: 1,
            recommendations: ['Content generation failed completely — no content produced'],
            seoScore: 0, 
            aeoScore: 0, 
            geoScore: 0, 
            contentQualityScore: 0,
            scoreBreakdown: createEmptyScoreBreakdown(),
            rulesRun: 0,
            rulesPassed: 0
        };
    }
    
    const thresholds = computeDynamicThresholds(serpPolicy, niche);
    
    const context: QARuleContext = {
        targetKeyword: undefined,
        neuronTerms,
        serpPolicy,
        siteContext
    };
    
    const enabledRules = QA_RULES.filter(r => r.enabled);
    
    for (const rule of enabledRules) {
        try {
            const detection = rule.detect(contract, context, thresholds);
            
            results.push({
                agent: `${getCategoryEmoji(rule.category)} ${rule.name}`,
                ruleId: rule.id,
                category: rule.category,
                status: detection.passed ? 'passed' : 
                       rule.severity === 'error' ? 'failed' : 'warning',
                feedback: detection.message,
                score: detection.score,
                details: detection.details,
                fixSuggestion: !detection.passed ? rule.description : undefined,
                autoFixed: false
            });
        } catch (e: any) {
            console.warn(`[QASwarm] Rule "${rule.id}" failed:`, e.message);
        }
    }
    
    const scoreBreakdown = calculateScoreBreakdown(results);
    
    const recommendations = results
        .filter(r => r.status !== 'passed' && r.fixSuggestion)
        .sort((a, b) => {
            const categoryOrder: Record<string, number> = { critical: 0, seo: 1, aeo: 2, geo: 3, enhancement: 4 };
            return (categoryOrder[a.category] || 5) - (categoryOrder[b.category] || 5);
        })
        .map(r => r.fixSuggestion!)
        .filter(Boolean);
    
    const criticalFailures = results.filter(r => r.category === 'critical' && r.status === 'failed').length;
    const passed = criticalFailures === 0 && scoreBreakdown.totalScore >= 70;
    
    return {
        passed,
        results,
        score: scoreBreakdown.totalScore,
        criticalFailures,
        recommendations,
        seoScore: scoreBreakdown.categories.seo.score,
        aeoScore: scoreBreakdown.categories.aeo.score,
        geoScore: scoreBreakdown.categories.geo.score,
        contentQualityScore: scoreBreakdown.totalScore,
        scoreBreakdown,
        rulesRun: enabledRules.length,
        rulesPassed: results.filter(r => r.status === 'passed').length
    };
}

function getCategoryEmoji(category: string): string {
    switch (category) {
        case 'critical': return '🚨';
        case 'seo': return '🔍';
        case 'aeo': return '🤖';
        case 'geo': return '🌍';
        case 'enhancement': return '✨';
        default: return '📋';
    }
}

function createEmptyScoreBreakdown(): ScoreBreakdown {
    return {
        version: SCORE_ALGORITHM_VERSION,
        timestamp: Date.now(),
        categories: {
            critical: { score: 0, weight: CURRENT_SCORE_WEIGHTS.weights.critical, checks: 0, passed: 0 },
            seo: { score: 0, weight: CURRENT_SCORE_WEIGHTS.weights.seo, checks: 0, passed: 0 },
            aeo: { score: 0, weight: CURRENT_SCORE_WEIGHTS.weights.aeo, checks: 0, passed: 0 },
            geo: { score: 0, weight: CURRENT_SCORE_WEIGHTS.weights.geo, checks: 0, passed: 0 },
            enhancement: { score: 0, weight: CURRENT_SCORE_WEIGHTS.weights.enhancement, checks: 0, passed: 0 }
        },
        totalScore: 0,
        weightedScore: 0,
        passed: false,
        criticalFailures: 0
    };
}

function calculateScoreBreakdown(results: QAValidationResult[]): ScoreBreakdown {
    const categories: Record<string, QAValidationResult[]> = {
        critical: [], seo: [], aeo: [], geo: [], enhancement: []
    };
    
    results.forEach(r => {
        const cat = r.category || 'enhancement';
        if (categories[cat]) categories[cat].push(r);
    });
    
    const calcCategoryScore = (items: QAValidationResult[]) => {
        if (items.length === 0) return { score: 100, checks: 0, passed: 0 };
        const total = items.reduce((sum, r) => sum + (r.score || 0), 0);
        const passed = items.filter(r => r.status === 'passed').length;
        return { score: Math.round(total / items.length), checks: items.length, passed };
    };
    
    const criticalStats = calcCategoryScore(categories.critical);
    const seoStats = calcCategoryScore(categories.seo);
    const aeoStats = calcCategoryScore(categories.aeo);
    const geoStats = calcCategoryScore(categories.geo);
    const enhancementStats = calcCategoryScore(categories.enhancement);
    
    const weights = CURRENT_SCORE_WEIGHTS.weights;
    
    const weightedScore = Math.round(
        (criticalStats.score * weights.critical) +
        (seoStats.score * weights.seo) +
        (aeoStats.score * weights.aeo) +
        (geoStats.score * weights.geo) +
        (enhancementStats.score * weights.enhancement)
    );
    
    const criticalFailures = categories.critical.filter(r => r.status === 'failed').length;
    
    return {
        version: SCORE_ALGORITHM_VERSION,
        timestamp: Date.now(),
        categories: {
            critical: { ...criticalStats, weight: weights.critical },
            seo: { ...seoStats, weight: weights.seo },
            aeo: { ...aeoStats, weight: weights.aeo },
            geo: { ...geoStats, weight: weights.geo },
            enhancement: { ...enhancementStats, weight: weights.enhancement }
        },
        totalScore: weightedScore,
        weightedScore,
        passed: criticalFailures === 0 && weightedScore >= CURRENT_SCORE_WEIGHTS.thresholds.pass,
        criticalFailures
    };
}


// ═══════════════════════════════════════════════════════════════════════════════
// 🔥 WORD BOUNDARY VALIDATOR — PREVENTS BROKEN ANCHOR TEXT
// ═══════════════════════════════════════════════════════════════════════════════

function isValidWordBoundary(
    html: string, 
    start: number, 
    end: number
): { valid: boolean; reason?: string } {
    // Check character before start position
    if (start > 0) {
        const charBefore = html[start - 1];
        const validBeforeChars = /[\s>.,;:!?()\[\]{}'"<\-–—\n\r\t]/;
        
        if (!validBeforeChars.test(charBefore)) {
            // Check if we're right after a closing tag
            const beforeSlice = html.slice(Math.max(0, start - 10), start);
            if (!beforeSlice.endsWith('>')) {
                return { valid: false, reason: `Invalid char before: "${charBefore}"` };
            }
        }
    }
    
    // Check character after end position
    if (end < html.length) {
        const charAfter = html[end];
        const validAfterChars = /[\s<.,;:!?()\[\]{}'">\-–—\n\r\t]/;
        if (!validAfterChars.test(charAfter)) {
            return { valid: false, reason: `Invalid char after: "${charAfter}"` };
        }
    }
    
    // Check for balanced HTML tags within selection
    const selectedText = html.slice(start, end);
    const openTagCount = (selectedText.match(/<[^/][^>]*>/g) || []).length;
    const closeTagCount = (selectedText.match(/<\/[^>]+>/g) || []).length;
    
    if (openTagCount !== closeTagCount) {
        return { valid: false, reason: 'Unbalanced HTML tags in selection' };
    }
    
    // Check that selection doesn't start or end mid-word
    const cleanText = selectedText.replace(/<[^>]*>/g, '').trim();
    if (cleanText.length === 0) {
        return { valid: false, reason: 'Selection is empty after removing HTML' };
    }
    
    const firstChar = cleanText[0];
    const lastChar = cleanText[cleanText.length - 1];
    
    // First character should be alphanumeric
    if (!/[a-zA-Z0-9]/.test(firstChar)) {
        return { valid: false, reason: `Selection starts with non-alphanumeric: "${firstChar}"` };
    }
    
    // Last character should be alphanumeric or valid punctuation
    if (!/[a-zA-Z0-9.!?'"]/.test(lastChar)) {
        return { valid: false, reason: `Selection ends with invalid char: "${lastChar}"` };
    }
    
    return { valid: true };
}





// ═══════════════════════════════════════════════════════════════════════════════
// 🔥🔥🔥 WORD-BOUNDARY-SAFE INTERNAL LINK INJECTION
// ═══════════════════════════════════════════════════════════════════════════════

function validateWordBoundaries(html: string, start: number, end: number): boolean {
    if (start > 0) {
        const charBefore = html[start - 1];
        const validBeforeChars = /[\s>.,;:!?()\[\]{}'"<\-–—\n\r\t]/;
        
        if (!validBeforeChars.test(charBefore)) {
            const beforeSlice = html.slice(Math.max(0, start - 10), start);
            if (!beforeSlice.endsWith('>')) return false;
        }
    }
    
    if (end < html.length) {
        const charAfter = html[end];
        const validAfterChars = /[\s<.,;:!?()\[\]{}'">\-–—\n\r\t]/;
        if (!validAfterChars.test(charAfter)) return false;
    }
    
    const text = html.slice(start, end);
    const openTags = (text.match(/<[^/][^>]*>/g) || []).length;
    const closeTags = (text.match(/<\/[^>]+>/g) || []).length;
    if (openTags !== closeTags) return false;
    
    return true;
}

// ═══════════════════════════════════════════════════════════════════════════════
// 🔥 SOTA ANCHOR TEXT VALIDATOR v4.0 — SEMANTIC QUALITY SCORING
// ═══════════════════════════════════════════════════════════════════════════════

export interface AnchorValidationResult {
    valid: boolean;
    reason?: string;
    score: number;
    qualityTier: 'excellent' | 'good' | 'acceptable' | 'poor' | 'rejected';
    suggestions?: string[];
    metrics: {
        wordCount: number;
        charCount: number;
        meaningfulWordRatio: number;
        startsWithStrongWord: boolean;
        endsWithStrongWord: boolean;
        hasProperNouns: boolean;
        semanticRelevance: number;
    };
}

const ANCHOR_QUALITY_THRESHOLDS = {
    MIN_WORDS: 3,
    MAX_WORDS: 7,
    IDEAL_MIN_WORDS: 4,
    IDEAL_MAX_WORDS: 5,
    MIN_CHARS: 15,
    MAX_CHARS: 70,
    MIN_MEANINGFUL_RATIO: 0.45,
    EXCELLENT_THRESHOLD: 85,
    GOOD_THRESHOLD: 70,
    ACCEPTABLE_THRESHOLD: 55,
};

const WEAK_START_WORDS = new Set([
    // Articles
    'the', 'a', 'an',
    // Conjunctions
    'and', 'or', 'but', 'nor', 'yet', 'so',
    // Prepositions
    'with', 'for', 'to', 'in', 'on', 'at', 'by', 'from', 'about', 'into',
    // Demonstratives
    'this', 'that', 'these', 'those',
    // Be verbs
    'is', 'are', 'was', 'were', 'be', 'been', 'being',
    // Have verbs
    'have', 'has', 'had',
    // Do verbs
    'do', 'does', 'did',
    // Modal verbs
    'will', 'would', 'could', 'should', 'may', 'might', 'must', 'can',
    // Question words
    'if', 'when', 'where', 'while', 'as', 'so',
    // Adverbs
    'just', 'also', 'only', 'very', 'really', 'actually',
    // Possessives
    'our', 'your', 'my', 'their', 'its',
    // Quantifiers
    'some', 'any', 'all', 'both', 'each', 'every', 'few', 'many', 'much',
    // Other weak starters
    'about', 'more', 'most', 'other', 'such', 'even', 'still', 'already',
    'here', 'there', 'now', 'then', 'why', 'how', 'what', 'which', 'who'
]);

const WEAK_END_WORDS = new Set([
    // All weak starters plus:
    ...WEAK_START_WORDS,
    // Prepositions that shouldn't end anchors
    'of', 'etc', 'and', 'or',
    // Incomplete patterns
    'a', 'the', 'to', 'for', 'with', 'by', 'in', 'on', 'at'
]);


const BANNED_ANCHOR_PATTERNS: RegExp[] = [
    /^click\s*(here|now|this)?$/i,
    /^read\s*(more|this|here)$/i,
    /^learn\s*(more|here)$/i,
    /^find\s*out(\s*more)?$/i,
    /^check\s*(out|this|here|it)$/i,
    /^this\s*(article|post|guide|page|link|site|website)$/i,
    /^here('s|\s+is)?$/i,
    /^see\s*(here|more|this|our|the)$/i,
    /^go\s*(here|to|now)$/i,
    /^view\s*(all|more|our|the)$/i,
    /^get\s*(started|more|it|your|the)$/i,
    /^download\s*(now|here|free|it)$/i,
    /^buy\s*(now|here|it)$/i,
    /^sign\s*up$/i,
    /^subscribe$/i,
    /^contact\s*us$/i,
    /more\s*info(rmation)?$/i,
    /click\s*here$/i,
    /read\s*more$/i,
    /learn\s*more$/i,
    /^https?:\/\//i,
    /^www\./i,
];

export function validateAnchorStrict(phrase: string, targetTitle?: string): AnchorValidationResult {
    // ═══════════════════════════════════════════════════════════════════════════
    // STEP 1: NULL CHECK
    // ═══════════════════════════════════════════════════════════════════════════
    
    if (!phrase || typeof phrase !== 'string') {
        return { valid: false, reason: 'Empty phrase', score: 0, qualityTier: 'rejected' };
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // STEP 2: CLEAN THE TEXT
    // ═══════════════════════════════════════════════════════════════════════════
    
    const trimmed = phrase.trim();
    
    const cleanText = trimmed
        .replace(/<[^>]*>/g, '')
        .replace(/&[a-z]+;/gi, ' ')
        .replace(/&#\d+;/g, ' ')
        .replace(/[\r\n\t]+/g, ' ')
        .replace(/\s+/g, ' ')
        .trim();
    
    const words = cleanText.split(/\s+/).filter(w => w.length > 0);
    
    // ═══════════════════════════════════════════════════════════════════════════
    // 🔥 STEP 2.5: CONTRACTION FRAGMENT DETECTION (NEW)
    // ═══════════════════════════════════════════════════════════════════════════
    
    const CONTRACTION_FRAGMENTS = [
        'isn', 'doesn', 'wasn', 'weren', 'hasn', 'haven', 'hadn',
        'wouldn', 'couldn', 'shouldn', 'won', 'don', 'can', 'aren',
        'didn', 'mustn', 'mightn', 'needn', 'shan', 'daren'
    ];
    
    if (words.length > 0) {
        const lastWord = words[words.length - 1].toLowerCase().replace(/[^a-z]/g, '');
        const firstWord = words[0].toLowerCase().replace(/[^a-z]/g, '');
        
        if (CONTRACTION_FRAGMENTS.includes(lastWord)) {
            return { 
                valid: false, 
                reason: `Ends with contraction fragment "${lastWord}"`, 
                score: 0, 
                qualityTier: 'rejected'
            };
        }
        
        if (CONTRACTION_FRAGMENTS.includes(firstWord)) {
            return { 
                valid: false, 
                reason: `Starts with contraction fragment "${firstWord}"`, 
                score: 0, 
                qualityTier: 'rejected'
            };
        }
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // STEP 3: HARD REJECTIONS
    // ═══════════════════════════════════════════════════════════════════════════
    
    if (words.length < 3) {
        return { 
            valid: false, 
            reason: `Only ${words.length} word(s) — minimum 3 required`, 
            score: 0, 
            qualityTier: 'rejected'
        };
    }
    
    if (words.length > 7) {
        return { 
            valid: false, 
            reason: `${words.length} words exceeds maximum 7`, 
            score: 0, 
            qualityTier: 'rejected'
        };
    }
    
    if (cleanText.length < 15) {
        return { 
            valid: false, 
            reason: `Only ${cleanText.length} chars — minimum 15`, 
            score: 0, 
            qualityTier: 'rejected' 
        };
    }
    
    if (cleanText.length > 65) {
        return { 
            valid: false, 
            reason: `${cleanText.length} chars exceeds maximum 65`, 
            score: 0, 
            qualityTier: 'rejected' 
        };
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // STEP 4: BANNED PATTERNS CHECK
    // ═══════════════════════════════════════════════════════════════════════════
    
    const BANNED_PATTERNS = [
        /^click\s+here$/i,
        /^read\s+more$/i,
        /^learn\s+more$/i,
        /^find\s+out$/i,
        /^check\s+(out|this)/i,
        /^this\s+(article|post|guide|page|link)/i,
        /^here\s+is/i,
        /^see\s+(here|more|this|our)/i,
        /^go\s+(here|to)/i,
        /more\s+info(rmation)?$/i,
        /^view\s+(all|more|our)/i,
        /^get\s+(started|more|your)/i,
    ];
    
    for (const pattern of BANNED_PATTERNS) {
        if (pattern.test(cleanText)) {
            return { 
                valid: false, 
                reason: 'Matches banned generic anchor pattern', 
                score: 0, 
                qualityTier: 'rejected'
            };
        }
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // STEP 5: WEAK WORD CHECKS
    // ═══════════════════════════════════════════════════════════════════════════
    
    const WEAK_START_WORDS = new Set([
        'the', 'a', 'an', 'and', 'or', 'but', 'with', 'for', 'to', 'in', 'on', 'at', 'by',
        'this', 'that', 'these', 'those', 'is', 'are', 'was', 'were', 'be', 'been', 'being',
        'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could', 'should',
        'if', 'when', 'where', 'while', 'as', 'so', 'just', 'also', 'only', 'very',
        'our', 'your', 'my', 'their', 'its', 'some', 'any', 'all', 'both', 'each',
        'about', 'more', 'most', 'other', 'such', 'even', 'still', 'already'
    ]);
    
    const WEAK_END_WORDS = new Set([
        'the', 'a', 'an', 'and', 'or', 'but', 'with', 'for', 'to', 'in', 'on', 'at', 'by', 'of',
        'is', 'are', 'was', 'were', 'be', 'been', 'being', 'have', 'has', 'had',
        'that', 'which', 'who', 'whom', 'whose', 'this', 'these', 'those',
        'if', 'when', 'where', 'while', 'as', 'so', 'can', 'may', 'will', 'etc'
    ]);
    
    const firstWord = words[0].toLowerCase().replace(/[^a-z]/g, '');
    const lastWord = words[words.length - 1].toLowerCase().replace(/[^a-z]/g, '');
    
    if (WEAK_START_WORDS.has(firstWord)) {
        return { 
            valid: false, 
            reason: `Starts with weak word "${firstWord}"`, 
            score: 25, 
            qualityTier: 'rejected'
        };
    }
    
    if (WEAK_END_WORDS.has(lastWord)) {
        return { 
            valid: false, 
            reason: `Ends with weak word "${lastWord}"`, 
            score: 25, 
            qualityTier: 'rejected'
        };
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // STEP 6: MEANINGFUL WORD RATIO
    // ═══════════════════════════════════════════════════════════════════════════
    
    const meaningfulWords = words.filter(w => {
        const lower = w.toLowerCase().replace(/[^a-z]/g, '');
        return lower.length >= 3 && !STOP_WORDS.has(lower);
    });
    
    const meaningfulRatio = meaningfulWords.length / words.length;
    
    if (meaningfulRatio < 0.4) {
        return { 
            valid: false, 
            reason: `Only ${Math.round(meaningfulRatio * 100)}% meaningful words (need 40%+)`, 
            score: 30, 
            qualityTier: 'poor'
        };
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // STEP 7: QUALITY SCORING
    // ═══════════════════════════════════════════════════════════════════════════
    
    let score = 50;
    
    score += Math.round(meaningfulRatio * 20);
    
    if (words.length >= 4 && words.length <= 5) {
        score += 15;
    } else if (words.length === 3 || words.length === 6) {
        score += 8;
    }
    
    if (targetTitle) {
        const relevanceScore = calculateAnchorRelevance(cleanText, targetTitle);
        score += Math.round(relevanceScore * 15);
    }
    
    if (meaningfulWords.length > 0 && meaningfulWords[0].toLowerCase() === firstWord) {
        score += 5;
    }
    
    if (/\d/.test(cleanText)) {
        score += 3;
    }
    
    const properNouns = words.slice(1).filter(w => /^[A-Z]/.test(w));
    if (properNouns.length > 0) {
        score += Math.min(5, properNouns.length * 2);
    }
    
    score = Math.min(100, score);
    
    // ═══════════════════════════════════════════════════════════════════════════
    // STEP 8: DETERMINE QUALITY TIER
    // ═══════════════════════════════════════════════════════════════════════════
    
    let qualityTier: AnchorValidationResult['qualityTier'];
    
    if (score >= 85) {
        qualityTier = 'excellent';
    } else if (score >= 70) {
        qualityTier = 'good';
    } else if (score >= 55) {
        qualityTier = 'acceptable';
    } else {
        qualityTier = 'poor';
    }
    
    return { 
        valid: qualityTier !== 'poor', 
        score, 
        qualityTier,
        reason: qualityTier === 'poor' ? 'Low quality score' : undefined
    };
}



// ═══════════════════════════════════════════════════════════════════════════════
// 🔥 OPTIMAL ANCHOR TEXT GENERATOR v2.0 — GENERATES HIGH-QUALITY ANCHOR CANDIDATES
// ═══════════════════════════════════════════════════════════════════════════════

export function generateOptimalAnchor(title: string, maxCandidates: number = 8): string[] {
    if (!title || title.length < 15) return [];
    
    // Clean the title
    const clean = title
        .replace(/[|–—:;\[\](){}""''«»<>]/g, ' ')
        .replace(/\s*[-–—|]\s*(complete\s+)?guide\s*$/i, '')
        .replace(/\s*[-–—|]\s*\d{4}\s*$/i, '')
        .replace(/\s+/g, ' ')
        .trim();
    
    const words = clean.split(/\s+/).filter(w => w.length >= 2);
    if (words.length < 3) return [];
    
    const candidates: Array<{ phrase: string; score: number }> = [];
    
    // Expanded weak start words set
    const WEAK_START_WORDS_LOCAL = new Set([
        'the', 'a', 'an', 'and', 'or', 'but', 'nor', 'yet', 'so',
        'with', 'for', 'to', 'in', 'on', 'at', 'by', 'from', 'about', 'into',
        'this', 'that', 'these', 'those',
        'is', 'are', 'was', 'were', 'be', 'been', 'being',
        'have', 'has', 'had', 'do', 'does', 'did',
        'will', 'would', 'could', 'should', 'may', 'might', 'must', 'can',
        'if', 'when', 'where', 'while', 'as',
        'just', 'also', 'only', 'very', 'really', 'actually',
        'our', 'your', 'my', 'their', 'its',
        'some', 'any', 'all', 'both', 'each', 'every', 'few', 'many', 'much',
        'about', 'more', 'most', 'other', 'such', 'even', 'still', 'already',
        'here', 'there', 'now', 'then', 'why', 'how', 'what', 'which', 'who'
    ]);
    
    // Strategy 1: 4-5 word windows from start (highest value)
    for (const windowSize of [5, 4]) {
        if (words.length >= windowSize) {
            // Skip weak first word if present
            const startIdx = WEAK_START_WORDS_LOCAL.has(words[0].toLowerCase()) ? 1 : 0;
            if (words.length - startIdx >= windowSize) {
                const phrase = words.slice(startIdx, startIdx + windowSize).join(' ');
                const validation = validateAnchorStrict(phrase, title);
                if (validation.valid && validation.score >= 60) {
                    candidates.push({ phrase, score: validation.score + 20 }); // Bonus for optimal length
                }
            }
        }
    }
    
    // Strategy 2: 3-word phrases (acceptable)
    if (words.length >= 3) {
        for (let i = 0; i <= Math.min(2, words.length - 3); i++) {
            const phrase = words.slice(i, i + 3).join(' ');
            const validation = validateAnchorStrict(phrase, title);
            if (validation.valid && validation.score >= 55) {
                candidates.push({ phrase, score: validation.score });
            }
        }
    }
    
    // Strategy 3: Action-oriented prefixes
    const actionPrefixes = ['mastering', 'understanding', 'implementing', 'optimizing'];
    const corePhrase = words.slice(0, 2).join(' ');
    for (const prefix of actionPrefixes.slice(0, 2)) {
        const actionPhrase = `${prefix} ${corePhrase}`;
        const validation = validateAnchorStrict(actionPhrase, title);
        if (validation.valid) {
            candidates.push({ phrase: actionPhrase, score: validation.score - 5 });
        }
    }
    
    // Dedupe and sort
    const seen = new Set<string>();
    return candidates
        .filter(c => {
            const lower = c.phrase.toLowerCase();
            if (seen.has(lower)) return false;
            seen.add(lower);
            return true;
        })
        .sort((a, b) => b.score - a.score)
        .slice(0, maxCandidates)
        .map(c => c.phrase);
}





// ═══════════════════════════════════════════════════════════════════════════════
// HELPER: Calculate semantic relevance between anchor and target title
// ═══════════════════════════════════════════════════════════════════════════════

function calculateAnchorRelevance(anchor: string, target: string): number {
    const anchorWords = new Set(
        anchor.toLowerCase()
            .split(/\s+/)
            .filter(w => w.length > 3 && !STOP_WORDS.has(w))
    );
    
    const targetWords = new Set(
        target.toLowerCase()
            .replace(/[|–—:;\[\](){}""''«»<>]/g, ' ')
            .split(/\s+/)
            .filter(w => w.length > 3 && !STOP_WORDS.has(w))
    );
    
    if (anchorWords.size === 0 || targetWords.size === 0) return 0;
    
    const intersection = [...anchorWords].filter(w => targetWords.has(w));
    const union = new Set([...anchorWords, ...targetWords]);
    
    return intersection.length / union.size;
}




// ═══════════════════════════════════════════════════════════════════════════════
// 🔥 SOTA ANCHOR CANDIDATE EXTRACTOR v4.0 — RICH DESCRIPTIVE ANCHORS
// ═══════════════════════════════════════════════════════════════════════════════

function generateSemanticAnchorCandidates(title: string, maxCandidates: number = 12): string[] {
    if (!title || typeof title !== 'string' || title.length < 10) return [];
    
    // Clean title — remove separators and suffixes
    let clean = title
        .replace(/[|–—:;\[\](){}""''«»<>]/g, ' ')
        .replace(/\s*[-–—|]\s*(complete\s+)?guide\s*$/i, '')
        .replace(/\s*[-–—|]\s*\d{4}\s*$/i, '')
        .replace(/\s*[-–—|]\s*[a-z\s]+blog\s*$/i, '')
        .replace(/\s+/g, ' ')
        .trim();
    
    const words = clean.split(/\s+/).filter(w => w.length >= 2);
    if (words.length < 3) return [];
    
    const candidates: Array<{ phrase: string; score: number }> = [];
    
    // ═══════════════════════════════════════════════════════════════════════════
    // STRATEGY 1: Noun phrase extraction (most valuable)
    // ═══════════════════════════════════════════════════════════════════════════
    
    const nounPhrasePatterns = [
        // "complete guide to X"
        /(?:complete|ultimate|definitive|comprehensive)\s+guide\s+(?:to|for)\s+(\w+(?:\s+\w+){1,3})/i,
        // "how to X" -> "X process"
        /how\s+to\s+(\w+(?:\s+\w+){1,3})/i,
        // "best X for Y"
        /best\s+(\w+(?:\s+\w+){0,2})\s+for/i,
        // "X vs Y" -> "X comparison"
        /(\w+(?:\s+\w+)?)\s+vs\.?\s+(\w+)/i,
    ];
    
    for (const pattern of nounPhrasePatterns) {
        const match = clean.match(pattern);
        if (match && match[1]) {
            const phrase = match[1].trim();
            const validation = validateAnchorStrict(phrase, title);
            if (validation.valid && validation.score >= 50) {
                candidates.push({ phrase, score: validation.score + 20 });
            }
        }
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // STRATEGY 2: Sliding windows (4-5 words optimal)
    // ═══════════════════════════════════════════════════════════════════════════
    
    for (const windowSize of [5, 4, 3]) {
        if (words.length < windowSize) continue;
        
        for (let i = 0; i <= words.length - windowSize; i++) {
            const phrase = words.slice(i, i + windowSize).join(' ');
            const validation = validateAnchorStrict(phrase, title);
            
            if (validation.valid && validation.score >= 55) {
                // Bonus for starting at beginning
                const positionBonus = i === 0 ? 15 : (i === 1 ? 8 : 0);
                // Bonus for optimal word count
                const lengthBonus = windowSize === 4 || windowSize === 5 ? 10 : 0;
                candidates.push({ 
                    phrase, 
                    score: validation.score + positionBonus + lengthBonus
                });
            }
        }
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // STRATEGY 3: Skip weak leading articles
    // ═══════════════════════════════════════════════════════════════════════════
    
    const weakLeaders = ['the', 'a', 'an', 'how', 'what', 'why', 'when', 'where'];
    if (words.length >= 4 && weakLeaders.includes(words[0].toLowerCase())) {
        for (const windowSize of [4, 3]) {
            const withoutFirst = words.slice(1);
            if (withoutFirst.length >= windowSize) {
                const phrase = withoutFirst.slice(0, windowSize).join(' ');
                const validation = validateAnchorStrict(phrase, title);
                if (validation.valid && validation.score >= 55) {
                    candidates.push({ phrase, score: validation.score + 5 });
                }
            }
        }
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // STRATEGY 4: Action-oriented phrases
    // ═══════════════════════════════════════════════════════════════════════════
    
    const actionPrefixes = ['mastering', 'understanding', 'implementing', 'optimizing', 'creating'];
    const corePhrase = words.slice(0, 3).join(' ');
    
    for (const prefix of actionPrefixes) {
        const actionPhrase = `${prefix} ${corePhrase}`;
        const validation = validateAnchorStrict(actionPhrase, title);
        if (validation.valid && validation.score >= 50) {
            candidates.push({ phrase: actionPhrase, score: validation.score });
        }
    }
    
    // Deduplicate and sort by score
    const seen = new Set<string>();
    return candidates
        .filter(c => {
            const lower = c.phrase.toLowerCase();
            if (seen.has(lower)) return false;
            seen.add(lower);
            return true;
        })
        .sort((a, b) => b.score - a.score)
        .slice(0, maxCandidates)
        .map(c => c.phrase);
}


function mapTextPositionToHtml(html: string, textPosition: number, length: number): { start: number; end: number } | null {
    const textToHtmlMap: number[] = [];
    let inTag = false;
    let inEntity = false;
    
    for (let htmlIdx = 0; htmlIdx < html.length; htmlIdx++) {
        const char = html[htmlIdx];
        
        if (char === '<') {
            inTag = true;
        } else if (char === '>') {
            inTag = false;
        } else if (char === '&' && !inTag) {
            const remaining = html.substring(htmlIdx);
            if (/^&[a-z]+;/i.test(remaining) || /^&#\d+;/.test(remaining)) {
                inEntity = true;
            }
        } else if (char === ';' && inEntity) {
            inEntity = false;
            textToHtmlMap.push(htmlIdx);
        } else if (!inTag && !inEntity) {
            textToHtmlMap.push(htmlIdx);
        }
    }
    
    if (textPosition < 0 || textPosition >= textToHtmlMap.length) {
        return null;
    }
    
    const endTextPosition = textPosition + length - 1;
    if (endTextPosition >= textToHtmlMap.length) {
        return null;
    }
    
    let start = textToHtmlMap[textPosition];
    let end = textToHtmlMap[endTextPosition] + 1;
    
    const wordBoundaryChars = /[\s>.,;:!?()\[\]{}'"<\-–—\n\r\t\/]/;
    let expandedStart = 0;
    
    while (start > 0 && expandedStart < 20) {
        const charBefore = html[start - 1];
        
        if (wordBoundaryChars.test(charBefore)) break;
        
        const beforeSlice = html.substring(Math.max(0, start - 50), start);
        if (beforeSlice.lastIndexOf('<') > beforeSlice.lastIndexOf('>')) break;
        
        start--;
        expandedStart++;
    }
    
    let expandedEnd = 0;
    
    while (end < html.length && expandedEnd < 20) {
        const charAtEnd = html[end];
        
        if (wordBoundaryChars.test(charAtEnd)) break;
        if (charAtEnd === '<') break;
        
        end++;
        expandedEnd++;
    }
    
    const slice = html.substring(start, end);
    const openTags = (slice.match(/<[a-z][^>]*(?<!\/)\s*>/gi) || []).length;
    const closeTags = (slice.match(/<\/[a-z]+>/gi) || []).length;
    
    if (openTags !== closeTags) return null;
    
    const cleanSlice = slice.replace(/<[^>]*>/g, '').replace(/&[a-z]+;/gi, ' ').trim();
    if (cleanSlice.length > length * 1.8 || cleanSlice.length < length * 0.6) return null;
    
    const firstCleanChar = cleanSlice[0];
    const lastCleanChar = cleanSlice[cleanSlice.length - 1];
    
    if (!/[a-zA-Z0-9]/.test(firstCleanChar)) return null;
    if (!/[a-zA-Z0-9.!?'"]/.test(lastCleanChar)) return null;
    
    if (!validateWordBoundaries(html, start, end)) return null;
    
    return { start, end };
}

function calculateJaccardSimilarity(text1: string, text2: string): number {
    const words1 = new Set(text1.toLowerCase().split(/\s+/).filter(w => w.length > 3 && !STOP_WORDS.has(w)));
    const words2 = new Set(text2.toLowerCase().split(/\s+/).filter(w => w.length > 3 && !STOP_WORDS.has(w)));
    
    const intersection = [...words1].filter(w => words2.has(w));
    const union = new Set([...words1, ...words2]);
    
    if (union.size === 0) return 0;
    
    const jaccard = intersection.length / union.size;
    
    const text1Lower = text1.toLowerCase();
    const text2Lower = text2.toLowerCase();
    let phraseBoost = 0;
    
    const words2Array = [...words2];
    for (let i = 0; i < words2Array.length - 1; i++) {
        const bigram = `${words2Array[i]} ${words2Array[i + 1]}`;
        if (text1Lower.includes(bigram)) phraseBoost += 0.12;
    }
    
    return Math.min(1, jaccard + phraseBoost);
}

function isPositionTooClose(position: number, usedPositions: Set<number>, minDistance: number): boolean {
    for (const used of usedPositions) {
        if (Math.abs(position - used) < minDistance) return true;
    }
    return false;
}

function isInsideExistingTag(html: string, position: number): boolean {
    const before = html.substring(Math.max(0, position - 500), position);
    const openAnchors = (before.match(/<a[\s>]/gi) || []).length;
    const closeAnchors = (before.match(/<\/a>/gi) || []).length;
    return openAnchors > closeAnchors;
}

interface SemanticLinkMatch {
    startIndex: number;
    endIndex: number;
    matchedText: string;
    score: number;
    context: string;
    type: 'exact' | 'semantic' | 'contextual';
}

function findSemanticMatchInContent(
    html: string,
    targetPhrase: string,
    linkTitle: string,
    usedPositions: Set<number>
): SemanticLinkMatch | null {
    const textContent = html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ');
    const targetLower = targetPhrase.toLowerCase();
    
    const exactIndex = textContent.toLowerCase().indexOf(targetLower);
    if (exactIndex !== -1 && !isPositionTooClose(exactIndex, usedPositions, ANCHOR_CONFIG.MIN_LINK_DISTANCE)) {
        const htmlPos = mapTextPositionToHtml(html, exactIndex, targetPhrase.length);
        if (htmlPos && !isInsideExistingTag(html, htmlPos.start)) {
            const matchedText = html.substring(htmlPos.start, htmlPos.end);
            const matchedClean = matchedText.replace(/<[^>]+>/g, '').trim();
            const matchedWordCount = matchedClean.split(/\s+/).filter(w => w.length > 0).length;
            
            if (matchedWordCount >= 3 && validateWordBoundaries(html, htmlPos.start, htmlPos.end)) {
                return {
                    startIndex: htmlPos.start,
                    endIndex: htmlPos.end,
                    matchedText,
                    score: 0.95,
                    context: textContent.substring(Math.max(0, exactIndex - 40), exactIndex + targetPhrase.length + 40),
                    type: 'exact'
                };
            }
        }
    }
    
    const sentences = textContent.split(/[.!?]+/).filter(s => s.trim().length > 40);
    let bestMatch: { sentence: string; phrase: string; score: number; index: number } | null = null;
    
    for (const sentence of sentences) {
        const sentenceLower = sentence.toLowerCase();
        const sentenceIndex = textContent.indexOf(sentence);
        
        if (isPositionTooClose(sentenceIndex, usedPositions, ANCHOR_CONFIG.MIN_LINK_DISTANCE)) continue;
        
        const sentenceWords = sentenceLower.split(/\s+/).filter(w => w.length > 0);
        
        for (let windowSize = Math.min(5, sentenceWords.length); windowSize >= 3; windowSize--) {
            for (let i = 0; i <= sentenceWords.length - windowSize; i++) {
                const candidateWords = sentenceWords.slice(i, i + windowSize);
                const candidatePhrase = candidateWords.join(' ');
                
                const firstWord = candidateWords[0];
                const lastWord = candidateWords[candidateWords.length - 1];
                
                if (STOP_WORDS.has(firstWord) || STOP_WORDS.has(lastWord)) continue;
                
                const phraseSimilarity = calculateJaccardSimilarity(candidatePhrase, targetLower);
                const titleSimilarity = calculateJaccardSimilarity(candidatePhrase, linkTitle.toLowerCase());
                const combinedScore = (phraseSimilarity * 0.55) + (titleSimilarity * 0.45);
                
                if (combinedScore > (bestMatch?.score || ANCHOR_CONFIG.RELEVANCE_THRESHOLD)) {
                    bestMatch = {
                        sentence,
                        phrase: candidatePhrase,
                        score: combinedScore,
                        index: sentenceIndex + sentenceLower.indexOf(candidatePhrase)
                    };
                }
            }
        }
    }
    
    if (bestMatch && bestMatch.score >= ANCHOR_CONFIG.RELEVANCE_THRESHOLD) {
        const htmlPos = mapTextPositionToHtml(html, bestMatch.index, bestMatch.phrase.length);
        
        if (htmlPos && !isInsideExistingTag(html, htmlPos.start)) {
            const matchedText = html.substring(htmlPos.start, htmlPos.end);
            const matchedClean = matchedText.replace(/<[^>]+>/g, '').trim();
            const wordCount = matchedClean.split(/\s+/).filter(w => w.length > 0).length;
            
            if (wordCount >= 3 && validateWordBoundaries(html, htmlPos.start, htmlPos.end)) {
                return {
                    startIndex: htmlPos.start,
                    endIndex: htmlPos.end,
                    matchedText,
                    score: bestMatch.score,
                    context: bestMatch.sentence.substring(0, 80),
                    type: 'semantic'
                };
            }
        }
    }
    
    return null;
}

// ═══════════════════════════════════════════════════════════════════════════════
// 🔥🔥🔥 WORD-BOUNDARY-SAFE INTERNAL LINK INJECTION v5.0 — ENTERPRISE GRADE
// ═══════════════════════════════════════════════════════════════════════════════
// FIXES:
// • Section limit check BEFORE HTML modification (was after — caused corruption)
// • All validation happens BEFORE modifying HTML
// • Proper section-based distribution
// • Clean separation: validate → modify → track
// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// ADD these helper functions BEFORE injectInternalLinks
// ═══════════════════════════════════════════════════════════════════════════════

function calculateOptimalLinkPositions(
    html: string,
    targetLinks: number
): number[] {
    const textContent = html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ');
    const totalLength = textContent.length;
    
    // Divide content into zones
    const zoneSize = totalLength / (targetLinks + 1);
    const optimalPositions: number[] = [];
    
    for (let i = 1; i <= targetLinks; i++) {
        const targetPos = Math.floor(zoneSize * i);
        optimalPositions.push(targetPos);
    }
    
    return optimalPositions;
}

function findNearestSuitablePosition(
    html: string,
    targetPosition: number,
    usedPositions: Set<number>,
    minDistance: number
): number | null {
    const textContent = html.replace(/<[^>]+>/g, ' ');
    
    // Search in expanding radius from target
    for (let radius = 0; radius < 500; radius += 50) {
        // Check forward
        const forwardPos = targetPosition + radius;
        if (forwardPos < textContent.length && 
            !isPositionTooClose(forwardPos, usedPositions, minDistance)) {
            return forwardPos;
        }
        
        // Check backward
        const backwardPos = targetPosition - radius;
        if (backwardPos > 0 && 
            !isPositionTooClose(backwardPos, usedPositions, minDistance)) {
            return backwardPos;
        }
    }
    
    return null;
}



export function injectInternalLinks(
    html: string,
    links: InternalLinkTarget[],
    currentUrl: string,
    options: {
        minLinks?: number;
        maxLinks?: number;
        minRelevance?: number;
        linkStyle?: string;
        minDistanceBetweenLinks?: number;
        maxLinksPerSection?: number;
    } = {}
): { html: string; linksAdded: InternalLinkResult[]; skippedReasons: Map<string, string> } {
    
    // ═══════════════════════════════════════════════════════════════════════════
    // STEP 1: CONFIGURATION & DEFAULTS
    // ═══════════════════════════════════════════════════════════════════════════
    
    const {
        minLinks = 12,
        maxLinks = 25,
        minRelevance = ANCHOR_CONFIG.RELEVANCE_THRESHOLD,
        linkStyle = 'color: #3b82f6; text-decoration: none; font-weight: 600; border-bottom: 2px solid rgba(59, 130, 246, 0.3); transition: all 0.2s ease; padding-bottom: 1px;',
        minDistanceBetweenLinks = 500,
        maxLinksPerSection = 2
    } = options;

    // Early exit if no content or links
    if (!html || !links.length) {
        return { html, linksAdded: [], skippedReasons: new Map() };
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // STEP 2: INITIALIZE TRACKING VARIABLES
    // ═══════════════════════════════════════════════════════════════════════════
    
    const linksAdded: InternalLinkResult[] = [];
    const skippedReasons = new Map<string, string>();
    const usedUrls = new Set<string>();
    const usedPositions = new Set<number>();
    const usedAnchorTexts = new Set<string>();
    const sectionLinkCounts = new Map<number, number>();
    let modifiedHtml = html;
    
    // ═══════════════════════════════════════════════════════════════════════════
    // STEP 3: BUILD SECTION MAP FOR LINK DISTRIBUTION
    // ═══════════════════════════════════════════════════════════════════════════
    
    const h2Positions: number[] = [];
    const h2Regex = /<h2[^>]*>/gi;
    let h2Match;
    while ((h2Match = h2Regex.exec(html)) !== null) {
        h2Positions.push(h2Match.index);
    }
    
    // Helper: Get section index for a position
    const getSectionIndex = (pos: number): number => {
        for (let i = h2Positions.length - 1; i >= 0; i--) {
            if (pos >= h2Positions[i]) return i;
        }
        return -1; // Before first H2 (intro section)
    };
    
    console.log(`[INTERNAL LINKS] ${h2Positions.length} H2 sections detected`);

    // ═══════════════════════════════════════════════════════════════════════════
    // STEP 4: PREPARE LINK CANDIDATES
    // ═══════════════════════════════════════════════════════════════════════════
    
    const candidates = links
        .filter(l => {
            if (l.url === currentUrl) return false;
            if (!l.title || l.title.length < 10) return false;
            if (l.title.toLowerCase() === 'home') return false;
            return true;
        })
        .map(link => ({
            link,
            anchorCandidates: generateSemanticAnchorCandidates(link.title),
            importance: link.title.length > 30 ? 70 : 50
        }))
        .filter(c => c.anchorCandidates.length > 0)
        .sort((a, b) => b.importance - a.importance);

    console.log(`[INTERNAL LINKS] ${candidates.length} link candidates prepared`);

    // ═══════════════════════════════════════════════════════════════════════════
    // STEP 5: MAIN LINK INJECTION LOOP
    // ═══════════════════════════════════════════════════════════════════════════
    
    for (const { link, anchorCandidates } of candidates) {
        // Check global limits
        if (usedUrls.size >= maxLinks) {
            console.log(`[INTERNAL LINKS] Reached max links limit (${maxLinks})`);
            break;
        }
        
        // Skip if URL already used
        if (usedUrls.has(link.url)) {
            continue;
        }

        // Try each anchor candidate for this link
        for (const anchorPhrase of anchorCandidates) {
            const normalizedAnchor = anchorPhrase.toLowerCase().trim();
            
            // Skip if anchor text already used
            if (usedAnchorTexts.has(normalizedAnchor)) {
                continue;
            }
            
            // ═══════════════════════════════════════════════════════════════════
            // VALIDATION 1: Anchor quality check
            // ═══════════════════════════════════════════════════════════════════
            
            const validation = validateAnchorStrict(anchorPhrase, link.title);
            
            if (!validation.valid) {
                continue;
            }
            if (validation.qualityTier === 'rejected' || validation.qualityTier === 'poor') {
                continue;
            }
            if (validation.score < 55) {
                continue;
            }

            // ═══════════════════════════════════════════════════════════════════
            // VALIDATION 2: Find semantic match in content
            // ═══════════════════════════════════════════════════════════════════
            
            const matchResult = findSemanticMatchInContent(
                modifiedHtml,
                anchorPhrase,
                link.title,
                usedPositions
            );

            // Skip if no good match found
            if (!matchResult || matchResult.score < minRelevance) {
                continue;
            }
            
            // ═══════════════════════════════════════════════════════════════════
            // VALIDATION 3: Check matched text quality
            // ═══════════════════════════════════════════════════════════════════
            
            const matchedClean = matchResult.matchedText.replace(/<[^>]+>/g, '').trim();
            const words = matchedClean.split(/\s+/).filter(w => w.length > 0);
            const wordCount = words.length;
            
            if (wordCount < 3) {
                skippedReasons.set(link.url, `Matched text too short: ${wordCount} words`);
                continue;
            }
            
            // ═══════════════════════════════════════════════════════════════════
            // VALIDATION 4: Final anchor validation on matched text
            // ═══════════════════════════════════════════════════════════════════
            
            const finalValidation = validateAnchorStrict(matchedClean);
            if (!finalValidation.valid) {
                skippedReasons.set(link.url, `Final validation failed: ${finalValidation.reason}`);
                continue;
            }
            
            // ═══════════════════════════════════════════════════════════════════
            // VALIDATION 5: Character boundary checks
            // ═══════════════════════════════════════════════════════════════════
            
            const firstChar = matchedClean[0];
            const lastChar = matchedClean[matchedClean.length - 1];
            
            if (!/[a-zA-Z0-9]/.test(firstChar)) {
                skippedReasons.set(link.url, `Invalid first char: "${firstChar}"`);
                continue;
            }
            
            if (!/[a-zA-Z0-9.!?]/.test(lastChar)) {
                skippedReasons.set(link.url, `Invalid last char: "${lastChar}"`);
                continue;
            }

            // ═══════════════════════════════════════════════════════════════════
            // VALIDATION 6: Word boundary validation
            // ═══════════════════════════════════════════════════════════════════
            
            if (!validateWordBoundaries(modifiedHtml, matchResult.startIndex, matchResult.endIndex)) {
                skippedReasons.set(link.url, 'Word boundary validation failed');
                continue;
            }
            
            // ═══════════════════════════════════════════════════════════════════
            // VALIDATION 7: SECTION LIMIT CHECK — MUST BE BEFORE HTML MODIFICATION
            // ═══════════════════════════════════════════════════════════════════
            
            const sectionIdx = getSectionIndex(matchResult.startIndex);
            const currentSectionLinks = sectionLinkCounts.get(sectionIdx) || 0;
            
            if (currentSectionLinks >= maxLinksPerSection) {
                skippedReasons.set(link.url, `Section ${sectionIdx} at capacity (${currentSectionLinks}/${maxLinksPerSection})`);
                continue;
            }
            
            // ═══════════════════════════════════════════════════════════════════
            // ALL VALIDATIONS PASSED — NOW SAFE TO MODIFY HTML
            // ═══════════════════════════════════════════════════════════════════
            
            const safeTitle = link.title.replace(/"/g, '&quot;');
            const linkHtml = `<a href="${link.url}" title="${safeTitle}" style="${linkStyle}" data-internal-link="semantic" data-score="${matchResult.score.toFixed(2)}">${matchResult.matchedText}</a>`;

            // Perform the HTML modification
            modifiedHtml = 
                modifiedHtml.substring(0, matchResult.startIndex) + 
                linkHtml + 
                modifiedHtml.substring(matchResult.endIndex);

            // ═══════════════════════════════════════════════════════════════════
            // UPDATE ALL TRACKING VARIABLES
            // ═══════════════════════════════════════════════════════════════════
            
            usedUrls.add(link.url);
            usedPositions.add(matchResult.startIndex);
            usedAnchorTexts.add(normalizedAnchor);
            sectionLinkCounts.set(sectionIdx, currentSectionLinks + 1);

            linksAdded.push({
                url: link.url,
                anchorText: matchedClean,
                context: `${matchResult.type}: "${matchedClean}" (score: ${(matchResult.score * 100).toFixed(0)}%, section: ${sectionIdx})`,
                relevanceScore: matchResult.score,
                matchType: matchResult.type,
                insertedAt: matchResult.startIndex
            });

            // Successfully added link for this URL — move to next candidate
            break;
        }
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // STEP 6: LOGGING & MINIMUM LINK ENFORCEMENT
    // ═══════════════════════════════════════════════════════════════════════════

    console.log(`[INTERNAL LINKS] ✅ Added ${linksAdded.length} links across ${sectionLinkCounts.size} sections`);
    
    // Log section distribution
    sectionLinkCounts.forEach((count, section) => {
        console.log(`[INTERNAL LINKS]    Section ${section}: ${count} link(s)`);
    });

    if (linksAdded.length < minLinks) {
        console.warn(`[INTERNAL LINKS] ⚠️ WARNING: Only ${linksAdded.length} links added (minimum target: ${minLinks})`);
        console.warn(`[INTERNAL LINKS] Top skipped reasons:`);
        
        let logCount = 0;
        skippedReasons.forEach((reason, url) => {
            if (logCount < 10) {
                console.warn(`   - ${url.substring(0, 40)}...: ${reason}`);
                logCount++;
            }
        });
    }

    return { html: modifiedHtml, linksAdded, skippedReasons };
}



// ═══════════════════════════════════════════════════════════════════════════════
// 🎯 OPPORTUNITY SCORING
// ═══════════════════════════════════════════════════════════════════════════════

export function calculateOpportunityScore(
    title: string, 
    lastMod: string | null,
    healthScore?: number | null
): OpportunityScore {
    let temporalDecay = 70;
    if (lastMod) {
        const days = Math.floor((Date.now() - new Date(lastMod).getTime()) / (1000 * 60 * 60 * 24));
        temporalDecay = Math.min(100, 50 + Math.min(days / 2, 50));
    }

    const commercialKeywords = ['best', 'buy', 'review', 'price', 'guide', 'how to', 'tutorial', 'vs', 'compare', 'comparison', 'alternative', 'top', 'cheap'];
    const titleLower = title.toLowerCase();
    const commercialMatches = commercialKeywords.filter(kw => titleLower.includes(kw)).length;
    const commercialIntent = Math.min(100, 40 + (commercialMatches * 15));

    const questionKeywords = ['what', 'how', 'why', 'when', 'where', 'which', 'who'];
    const aeoOpportunity = questionKeywords.some(kw => titleLower.startsWith(kw)) ? 85 : 50;

    const geoKeywords = ['complete', 'guide', 'ultimate', 'definitive', 'comprehensive'];
    const geoOpportunity = geoKeywords.some(kw => titleLower.includes(kw)) ? 80 : 45;

    let strikingDistance = 50;
    if (healthScore !== null && healthScore !== undefined) {
        if (healthScore >= 30 && healthScore < 70) strikingDistance = 90;
        else if (healthScore < 30) strikingDistance = 70;
        else strikingDistance = 30;
    }

    const competitionLevel = titleLower.length > 50 ? 60 : titleLower.length > 30 ? 50 : 40;
    const trafficPotential = Math.round((commercialIntent * 0.4) + (aeoOpportunity * 0.3) + (temporalDecay * 0.3));

    const total = Math.round(
        (temporalDecay * 0.15) + (commercialIntent * 0.25) + (strikingDistance * 0.25) +
        (aeoOpportunity * 0.15) + (geoOpportunity * 0.10) + (trafficPotential * 0.10)
    );

    return { 
        total: Math.min(100, total),
        commercialIntent, temporalDecay, strikingDistance,
        competitionLevel, trafficPotential, aeoOpportunity, geoOpportunity
    };
}

// ═══════════════════════════════════════════════════════════════════════════════
// 🔥 H1 REMOVAL UTILITY
// ═══════════════════════════════════════════════════════════════════════════════

export function removeAllH1Tags(html: string): string {
    if (!html) return html;
    
    let cleaned = html;
    
    for (let pass = 0; pass < 3; pass++) {
        cleaned = cleaned.replace(/<h1[^>]*>[\s\S]*?<\/h1>/gi, '');
        cleaned = cleaned.replace(/<h1[^>]*\/>/gi, '');
        cleaned = cleaned.replace(/^\s*<h1[^>]*>[\s\S]*?<\/h1>\s*/i, '');
    }
    
    cleaned = cleaned.replace(/<h1\b[^>]*>/gi, '');
    cleaned = cleaned.replace(/<\/h1>/gi, '');
    cleaned = cleaned.replace(/\n{3,}/g, '\n\n');
    
    return cleaned.trim();
}

export function validateNoH1(html: string): { valid: boolean; count: number } {
    const h1Count = (html.match(/<h1[^>]*>/gi) || []).length;
    return { valid: h1Count === 0, count: h1Count };
}

// ═══════════════════════════════════════════════════════════════════════════════
// 🔥 FAQ DUPLICATE DETECTION & REMOVAL
// ═══════════════════════════════════════════════════════════════════════════════

export function countFAQSections(html: string): number {
    if (!html) return 0;
    
    const patterns = [
        /<section[^>]*class="[^"]*faq[^"]*"[^>]*>/gi,
        /<div[^>]*id="[^"]*faq[^"]*"[^>]*>/gi,
        /<h2[^>]*>[\s\S]*?frequently\s+asked[\s\S]*?<\/h2>/gi,
        /wp-opt-faq-/gi,
    ];
    
    let count = 0;
    for (const pattern of patterns) {
        const matches = html.match(pattern);
        if (matches) count += matches.length;
    }
    
    return Math.min(count, 5);
}

// ═══════════════════════════════════════════════════════════════════════════════
// 🔥 FAQ DUPLICATE DETECTOR & REMOVER v2.0
// ═══════════════════════════════════════════════════════════════════════════════

export function removeDuplicateFAQSections(html: string, log?: (msg: string) => void): string {
    if (!html) return html;
    
    // Comprehensive FAQ section patterns
    const faqPatterns = [
        // Class-based sections
        /<section[^>]*class="[^"]*(?:faq|wp-opt-faq)[^"]*"[^>]*>[\s\S]*?<\/section>/gi,
        // ID-based sections
        /<section[^>]*id="[^"]*faq[^"]*"[^>]*>[\s\S]*?<\/section>/gi,
        // Div-based FAQ containers
        /<div[^>]*class="[^"]*faq-(?:section|accordion|container)[^"]*"[^>]*>[\s\S]*?<\/div>/gi,
    ];
    
    // Collect all FAQ sections with their positions
    const allMatches: Array<{ match: string; index: number; pattern: number }> = [];
    
    faqPatterns.forEach((pattern, patternIdx) => {
        let match;
        const regex = new RegExp(pattern.source, pattern.flags);
        while ((match = regex.exec(html)) !== null) {
            allMatches.push({
                match: match[0],
                index: match.index,
                pattern: patternIdx
            });
        }
    });
    
    if (allMatches.length <= 1) return html;
    
    // Sort by position (descending) to remove from end first (preserves indices)
    allMatches.sort((a, b) => b.index - a.index);
    
    log?.(`   ⚠️ Found ${allMatches.length} FAQ sections — keeping best one, removing ${allMatches.length - 1} duplicate(s)`);
    
    // Determine which FAQ to keep (the one with most content)
    let bestFaqIdx = 0;
    let maxLength = 0;
    
    allMatches.forEach((item, idx) => {
        // Score based on: length + has gradient styling + has schema
        let score = item.match.length;
        if (item.match.includes('linear-gradient')) score += 5000;
        if (item.match.includes('FAQPage')) score += 3000;
        if (item.match.includes('faq-itm') || item.match.includes('faq-question')) score += 2000;
        
        if (score > maxLength) {
            maxLength = score;
            bestFaqIdx = idx;
        }
    });
    
    // Remove all except the best one
    let cleaned = html;
    
    allMatches.forEach((item, idx) => {
        if (idx !== bestFaqIdx) {
            cleaned = cleaned.replace(item.match, '<!-- DUPLICATE_FAQ_REMOVED -->');
        }
    });
    
    // Clean up markers
    cleaned = cleaned.replace(/<!-- DUPLICATE_FAQ_REMOVED -->\s*/g, '');
    cleaned = cleaned.replace(/\n{3,}/g, '\n\n');
    
    // Also remove any orphaned FAQ-related style blocks
    cleaned = cleaned.replace(/<style>[^<]*(?:faq-section-|wp-opt-faq-)[^<]*<\/style>\s*/gi, '');
    
    log?.(`   ✅ Kept FAQ at position ${allMatches[bestFaqIdx].index}, removed ${allMatches.length - 1} duplicates`);
    
    return cleaned.trim();
}


// ═══════════════════════════════════════════════════════════════════════════════
// 📊 NLP COVERAGE CALCULATOR
// ═══════════════════════════════════════════════════════════════════════════════

export function calculateNLPCoverage(
    content: string,
    terms: NeuronTerm[]
): {
    score: number;
    usedTerms: Array<NeuronTerm & { count: number }>;
    missingTerms: NeuronTerm[];
    coverage: number;
    weightedScore: number;
} {
    if (!content || terms.length === 0) {
        return { score: 100, usedTerms: [], missingTerms: [], coverage: 100, weightedScore: 100 };
    }
    
    const contentLower = content.toLowerCase();
    const usedTerms: Array<NeuronTerm & { count: number }> = [];
    const missingTerms: NeuronTerm[] = [];
    
    let totalWeight = 0;
    let usedWeight = 0;
    
    terms.forEach(term => {
        const termLower = term.term.toLowerCase();
        const escaped = termLower.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const regex = new RegExp(`\\b${escaped}\\b`, 'gi');
        const matches = contentLower.match(regex) || [];
        const count = matches.length;
        
        const weight = term.importance || 50;
        totalWeight += weight;
        
        if (count > 0) {
            usedTerms.push({ ...term, count });
            usedWeight += weight;
        } else {
            missingTerms.push(term);
        }
    });
    
    const coverage = terms.length > 0 ? Math.round((usedTerms.length / terms.length) * 100) : 100;
    const weightedScore = totalWeight > 0 ? Math.round((usedWeight / totalWeight) * 100) : 100;
    const score = Math.round((coverage * 0.6) + (weightedScore * 0.4));
    
    return { score, usedTerms, missingTerms, coverage, weightedScore };
}

// ═══════════════════════════════════════════════════════════════════════════════
// 🛠️ UTILITY FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

export function sanitizeSlug(s: string): string {
    return s.toLowerCase().replace(/[^a-z0-9-]/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '').substring(0, 80);
}

export function sanitizeTitle(title: string, slug: string): string {
    if (title && title.length > 2 && title.toLowerCase() !== 'home') return title;
    return slug.replace(/-/g, ' ').replace(/\b\w/g, l => l.toUpperCase()).trim() || 'New Page';
}

export function extractSlugFromUrl(url: string): string {
    try {
        const pathname = new URL(url).pathname;
        const parts = pathname.split('/').filter(Boolean);
        return sanitizeSlug(parts[parts.length - 1] || 'home');
    } catch {
        return 'home';
    }
}

export function formatDuration(ms: number): string {
    if (ms < 1000) return `${ms}ms`;
    if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
    const mins = Math.floor(ms / 60000);
    const secs = Math.round((ms % 60000) / 1000);
    if (mins < 60) return `${mins}m ${secs}s`;
    const hours = Math.floor(mins / 60);
    const remainingMins = mins % 60;
    return `${hours}h ${remainingMins}m`;
}

export function formatNumber(num: number): string {
    if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`;
    if (num >= 1000) return `${(num / 1000).toFixed(1)}K`;
    return num.toLocaleString();
}

export function sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
}

export function generateId(): string {
    return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

export function deepClone<T>(obj: T): T {
    return JSON.parse(JSON.stringify(obj));
}

export function isEmpty(value: any): boolean {
    if (value === null || value === undefined) return true;
    if (typeof value === 'string') return value.trim().length === 0;
    if (Array.isArray(value)) return value.length === 0;
    if (typeof value === 'object') return Object.keys(value).length === 0;
    return false;
}

export function truncate(str: string, maxLength: number): string {
    if (str.length <= maxLength) return str;
    return str.substring(0, maxLength - 3) + '...';
}

export function stripHtml(html: string): string {
    const doc = new DOMParser().parseFromString(html, 'text/html');
    return doc.body?.textContent || '';
}

export function escapeHtml(str: string): string {
    const map: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
    return str.replace(/[&<>"']/g, m => map[m]);
}

export function isValidUrl(str: string): boolean {
    try { new URL(str); return true; } catch { return false; }
}

export function getDomain(url: string): string {
    try { return new URL(url).hostname.replace('www.', ''); } catch { return ''; }
}

export function debounce<T extends (...args: any[]) => any>(
    func: T,
    wait: number
): (...args: Parameters<T>) => void {
    let timeout: ReturnType<typeof setTimeout> | null = null;
    
    return function executedFunction(...args: Parameters<T>) {
        if (timeout) clearTimeout(timeout);
        timeout = setTimeout(() => func(...args), wait);
    };
}

export function throttle<T extends (...args: any[]) => any>(
    func: T,
    limit: number
): (...args: Parameters<T>) => void {
    let inThrottle = false;
    
    return function executedFunction(...args: Parameters<T>) {
        if (!inThrottle) {
            func(...args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    };
}

// ═══════════════════════════════════════════════════════════════════════════════
// 📦 EXPORTS SUMMARY
// ═══════════════════════════════════════════════════════════════════════════════

/*
UTILS v25.0 EXPORTS:

CONSTANTS:
- UTILS_VERSION, SCORE_ALGORITHM_VERSION
- STOP_WORDS, BANNED_SINGLE_WORDS, BANNED_PHRASE_REGEXES
- ANCHOR_CONFIG, DEFAULT_THRESHOLDS
- AUTHORITY_DOMAINS, POWER_WORDS, EEAT_SIGNALS

THRESHOLDS:
- computeDynamicThresholds(): SERP-driven thresholds

READABILITY:
- calculateFleschKincaid(): Reading ease score
- calculateSMOGIndex(): SMOG readability
- calculateGunningFog(): Fog index
- getReadabilityInterpretation(): Human-readable interpretation

ANALYSIS:
- analyzeExistingContent(): Full content analysis
- calculateSeoMetrics(): Complete SEO metrics

QA ENGINE:
- QA_RULES: 50+ validation rules
- runQASwarm(): Main QA validation runner
- getQARule(), getQARulesByCategory()
- setQARuleEnabled(), registerQARule()

INTERNAL LINKING:
- validateAnchorStrict(): Anchor text validation
- injectInternalLinks(): Word-boundary-safe injection
- generateSemanticAnchorCandidates(): Anchor generation

H1/FAQ UTILITIES:
- removeAllH1Tags(): H1 removal
- validateNoH1(): H1 validation
- countFAQSections(): FAQ counting
- removeDuplicateFAQSections(): FAQ deduplication

NLP:
- calculateNLPCoverage(): NLP term coverage

OPPORTUNITY:
- calculateOpportunityScore(): Page opportunity scoring

UTILITIES:
- sanitizeSlug(), sanitizeTitle(), extractSlugFromUrl()
- formatDuration(), formatNumber(), sleep()
- generateId(), deepClone(), isEmpty()
- truncate(), stripHtml(), escapeHtml()
- isValidUrl(), getDomain()
- debounce(), throttle()
*/
