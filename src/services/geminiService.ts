
import { GoogleGenAI } from "@google/genai";

// Strictly adhering to guidelines: use process.env.API_KEY directly in the constructor.
const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });

export const getAIHint = async (challengeTitle: string, userQuery: string) => {
  try {
    const response = await ai.models.generateContent({
      model: 'gemini-3-flash-preview',
      contents: `User is stuck on a CTF challenge "${challengeTitle}". Query: "${userQuery}". 
      Respond as "Omar", a friendly and simple hacker mentor. 
      Break down the problem into very easy, simple steps. Explain *why* things work. 
      Do not give the flag directly, but guide them to the answer. Use simple language.`,
      config: {
        systemInstruction: "You are Omar, a simple-speaking hacker mentor who loves teaching. You use emojis and explain things like the user is a beginner. You use purple branding in your mind.",
      }
    });
    return response.text;
  } catch (error) {
    console.error("Gemini Error:", error);
    return "Hey, Omar here. Looks like the connection is fuzzy. Try again in a bit!";
  }
};
