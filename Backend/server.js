import express from 'express';
import { scanGitHubRepository } from './scanners/github-scanner.js';
import { GoogleAuth } from 'google-auth-library';
import scanDirectory from './scanners/file-scanner.js';
import { TextServiceClient } from '@google-ai/generativelanguage';
import scanFiles from './scanners/pii-localScanner.js';
import { analyzeLocalDirectory, analyzeGitHubRepository } from './utils/language-analyzer.js';
import { Octokit } from 'octokit';
import cors from 'cors';
import dotenv from "dotenv";
import remainingRequest from './utils/request-remaining.js';
import mailData from './utils/mail.js';
import Project from './models/project.model.js';
import ScanReport from './models/scanReport.model.js';
import connectToMongoDB from './db.js';
import autoPopulate from './utils/autoPopulate.js';
import mongoose from 'mongoose';
import User from './models/user.model.js';
import bcrypt from 'bcryptjs'
import cookieParser from 'cookie-parser';
import generateTokenAndSetCookie from './utils/generateToken.js';
import logger from './utils/logger.js';
import authRoutes from './routes/auth.js';
import { scanFileContent } from './scanners/pii-scanner.js';
import fetchRemoteLogFile from './utils/fetchRemoteLogFile.js';

dotenv.config();
const app = express();
const port = 3000;

app.use(express.json());
app.use(cookieParser())
app.use(cors({
  origin: function (origin, callback) {
    callback(null, true);
  },
  credentials: true
}));

const octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });

app.post('/signup', async (req, res) => {
  const { username, password, confirmPassword } = req.body;

  if (password !== confirmPassword) {
    return res.status(400).send({ msg: "The passwords do not match" });
  }

  const userExists = await User.findOne({ username });
  if (userExists) {
    return res.status(400).send({ msg: "User already exists" });
  }

  try {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = new User({ username, password: hashedPassword });

    if (newUser) {
      await newUser.save();
      logger.info('User created successfully', { username });
      return res.status(200).send({ msg: `User ${newUser.username} has been created` });
    } else {
      logger.error('Error during user creation', { username, error: err.message });
      return res.status(400).send({ msg: "Invalid user data" });
    }
  } catch (err) {
    res.status(500).send({ msg: "An error occurred", error: err.message });
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(400).send({ msg: "User does not exist" });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).send({ msg: "Invalid Credentials" });
    }

    generateTokenAndSetCookie(username, res);
    return res.status(200).send({ msg: `User ${username} logged in` });
  } catch (err) {
    logger.error('Error during login', { username, error: err.message });
    return res.status(500).send({ msg: "Internal Server Error", error: err.message });
  }
});

app.get('/user', (req, res) => {
  const token = req.cookies.jwt; // Use the correct cookie name
  if (!token) {
    logger.warn('Unauthorized access attempt');
    return res.status(401).send({ msg: 'Unauthorized' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    res.status(200).send({ username: decoded.username });
  } catch (err) {
    console.error("JWT verification failed:", err.message); // Log the error
    res.status(401).send({ msg: 'Unauthorized' });
  }
});

app.post('/logout', (req, res) => {
  res.clearCookie('jwt'); // Use the correct cookie name
  logger.info('User logged out');
  res.status(200).send({ msg: 'Logged out' });
});

app.post('/scan-github', async (req, res) => {
  const { owner, repo, regexPairs } = req.body;

  try {
    const piiVulnerabilities = await scanGitHubRepository(owner, repo, regexPairs);
    res.json(piiVulnerabilities);
  } catch (error) {
    logger.error('Error scanning GitHub repository:', error);
    logger.error(error.stack);
    res.status(500).json({ error: 'Failed to scan GitHub repository' });
  }
});

app.post('/scan-directory', (req, res) => {
  const { directoryPath, regexPairs } = req.body;

  if (!directoryPath || typeof directoryPath !== 'string') {
    return res.status(400).json({ error: 'Invalid or missing directoryPath in request body' });
  }

  if (!regexPairs || typeof regexPairs !== 'object') {
    return res.status(400).json({ error: 'Invalid or missing regexPairs in request body' });
  }

  try {
    const filePaths = scanDirectory(directoryPath);
    const piiVulnerabilities = scanFiles(filePaths, regexPairs);

    res.json(piiVulnerabilities);
  } catch (error) {
    logger.error('Error scanning directory:', error);
    res.status(500).json({ error: 'Failed to scan directory', details: error.message });
  }
});

app.post('/scan-remote-log', async (req, res) => {
  const {
    host,
    port,
    logusername,
    privateKeyPath,
    logFilePath,
    regexPairs
  } = req.body;

  if (!host || !logusername || !privateKeyPath || !logFilePath || !regexPairs) {
    return res.status(400).json({ error: 'Missing required parameters' });
  }

  try {
    console.log('Fetching remote log file for scanning...');
    const logContent = await fetchRemoteLogFile({
      host,
      port: port || 22,
      logusername,
      privateKeyPath,
      logFilePath
    });

    console.log('Scanning file content...');
    const piiVulnerabilities = scanFileContent(logContent, regexPairs);

    // Analyze log content
    const logStats = analyzeLogContent(logContent);

    // Combine vulnerabilities and log stats
    const result = {
      vulnerabilities: piiVulnerabilities,
      logStats: logStats
    };

    res.json(result);
  } catch (error) {
    console.error('Error in /scan-remote-log:', error);
    res.status(500).json({ error: 'Failed to scan remote log file', details: error.message });
  }
});

app.post('/dynamic-log-stats', async (req, res) => {
  const { host, port, logusername, privateKeyPath, logFilePath } = req.body;

  if (!host || !port || !logusername || !privateKeyPath || !logFilePath) {
    return res.status(400).json({ error: 'Missing required fields in request body' });
  }

  try {
    console.log('Fetching remote log file...');
    const logContent = await fetchRemoteLogFile({ host, port, logusername, privateKeyPath, logFilePath });
    console.log('Analyzing log content...');
    const logStats = analyzeLogContent(logContent);
    res.json(logStats);
  } catch (error) {
    console.error('Error in /dynamic-log-stats:', error);
    res.status(500).json({ error: 'Failed to fetch or analyze log file', details: error.message });
  }
});

app.post('/github-repo-stats', async (req, res) => {
  const { owner, repo } = req.body;

  if (!owner || typeof owner !== 'string') {
    return res.status(400).json({ error: 'Invalid or missing owner in request body' });
  }

  if (!repo || typeof repo !== 'string') {
    return res.status(400).json({ error: 'Invalid or missing repo in request body' });
  }

  try {
    const languageStats = await analyzeGitHubRepository(owner, repo, octokit);
    res.json(languageStats);
  } catch (error) {
    logger.error('Error analyzing GitHub repository:', error);
    res.status(500).json({ error: 'Failed to analyze GitHub repository', details: error.message });
  }
});

app.post('/local-directory-stats', async (req, res) => {
  const { directoryPath } = req.body;

  if (!directoryPath || typeof directoryPath !== 'string') {
    return res.status(400).json({ error: 'Invalid or missing directoryPath in request body' });
  }

  try {
    const languageStats = await analyzeLocalDirectory(directoryPath);//extensions to be scanned are written manually right now. Try to get some fix for that
    res.json(languageStats);
  } catch (error) {
    logger.error('Error analyzing local directory:', error);
    res.status(500).json({ error: 'Failed to analyze local directory', details: error.message });
  }
});

app.post("/email", async (req, res) => {
  console.log("Received email request:", req.body);
  const { jsonData, receiverEmail } = req.body
  try {
    const result = await mailData(jsonData, receiverEmail)
    return res.status(200).json({ message: "Email sent successfully", result })
  } catch (err) {
    logger.error("Error sending email:", err)
    return res.status(500).json({ error: "Unable to send email" })
  }
})

app.get('/remaining_requests', async (req, res) => {
  try {
    const rem = await remainingRequest()
    res.send(`Number of Remaining Request: ${rem}`)
  } catch (err) {
    return res.send("Unable to Fetch Remaining Request")
  }
})

app.get('/getAllProjects', async (req, res) => {
  try {
    const projects = await Project.find()
      .sort({ lastScanAt: -1 })
      .limit(10)  // Limit to the 10 most recently scanned projects
      .populate({
        path: 'scans',
        options: { sort: { timestamp: -1 } }
      });

    res.json(projects);
  } catch (error) {
    logger.error('Error fetching projects', { error: error.message });
    res.status(500).json({ message: error.message });
  }
});

app.get('/getReport/:reportId', async (req, res) => {
  try {
    let report = await ScanReport.findById(req.params.reportId).populate('project', 'projectName');

    if (!report) {
      report = await DynamicScanReport.findById(req.params.reportId).populate('project', 'projectName');
    }

    if (!report) {
      return res.status(404).json({ message: 'Report not found' });
    }

    res.json(report);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.post('/createReport', async (req, res) => {
  const { projectName, username, reportData, scanType } = req.body;

  try {
    let project = await Project.findOne({ projectName });

    if (!project) {
      project = new Project({ projectName });
    }

    const scanReport = new ScanReport({
      username,
      project: project._id,
      scanType,
      reportData: {
        scanDetails: reportData.scanDetails,
        stats: reportData.stats,
        logStats: reportData.logStats,
        vulnerabilities: reportData.vulnerabilities,
      },
    });

    await scanReport.save();

    project.scans.push(scanReport._id);
    project.lastScanAt = scanReport.timestamp;
    await project.save();

    res.status(201).json(scanReport);
  } catch (error) {
    logger.error('Error creating report', { projectName, username, error: error.message });
    res.status(400).json({ message: error.message });
  }
});

app.get('/api/scanReports', async (req, res) => {
  try {

    const database = mongoose.connection.db;
    const collection = database.collection('scanreports');
    const documents = await collection.find({}).toArray();

    let keyCounts = {};
    let totalKeys = 0;

    // Loop through all documents in the reports and count occurrences of each key in scanDetails
    documents.forEach(doc => {
      if (doc.reportData && doc.reportData.scanDetails) {
        for (let key in doc.reportData.scanDetails) {
          if (doc.reportData.scanDetails.hasOwnProperty(key)) {
            keyCounts[key] = (keyCounts[key] || 0) + 1;
            totalKeys++;
          }
        }
      }
    });

    // Calculate percentages of the each pii in the scanDetals 
    let keyPercentages = {};
    for (let key in keyCounts) {
      if (keyCounts.hasOwnProperty(key)) {
        keyPercentages[key] = Math.round((keyCounts[key] / totalKeys) * 100) + "%";
      }
    }

    // Send the result as a JSON response 
    res.json({
      keyCounts: keyCounts,
      keyPercentages: keyPercentages
    });
  } catch (error) {
    console.error('Error fetching data:', error.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.delete('/deleteProject/:projectId', async (req, res) => {
  const { projectId } = req.params

  const session = await mongoose.startSession()
  session.startTransaction()

  try {
    const project = await Project.findById(projectId).session(session)
    if (!project) {
      await session.abortTransaction()
      session.endSession()
      res.status(404).send({
        msg: "Project Not found for the Id given"
      })
      return
    }

    await ScanReport.deleteMany({ project: projectId }).session(session)
    await Project.findByIdAndDelete(projectId).session(session)

    await session.commitTransaction();
    session.endSession();

    res.status(200).send({
      msg: "This project and its associated scans have been deleted"
    })

  } catch (err) {
    logger.error('Error deleting project', { projectId, error: err.message });
    await session.abortTransaction();
    session.endSession();

    res.status(500).send({
      msg: "Something went wrong",
      error: err.message
    })
  }
})

app.delete('/deleteScan/:scanId', async (req, res) => {
  const { scanId } = req.params

  try {
    const scan = await ScanReport.findById(scanId);
    if (!scan) {
      res.status(404).send({
        msg: "Scan does not exist"
      })
      return
    }

    const project = await Project.findById(scan.project)
    if (!project) {
      res.status(404).send({
        msg: "Project Not found"
      })
      return
    }

    project.scans = project.scans.filter(id => !id.equals(scanId))
    await project.save()

    await ScanReport.findByIdAndDelete(scanId)
    res.status(200).send({
      msg: "Scan deleted Successfully"
    })

  } catch (error) {
    res.status(500).send({
      msg: "Error Occured",
      error: error.message
    })
  }
})

app.post("/regexValue", async (req, res) => {
  const { data } = req.body;
  const response = await autoPopulate(data)
  return res.json(response)
})

const MAX_RETRIES = 10;

app.post('/gemini-chat', async (req, res) => {
  const { message } = req.body;
  const client = new TextServiceClient({
    authClient: new GoogleAuth().fromAPIKey(process.env.GEMINI_API_KEY),
  });

  const generatePrompt = (msg, attempt) => {
    if (attempt === 0) {
      return `Provide the object structure for PII data for ${msg}. The output should be in the form of a JSON object where each key represents a type of PII and its value is a regex pattern that matches that PII.`;
    } else {
      return `Provide the object structure for PII data for ${msg}. The output should be in the form of a JSON object where each key represents a type of PII and its value is a regex pattern that matches that PII.`;
    }
  };

  for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
    try {
      const prompt = generatePrompt(message, attempt);
      const result = await client.generateText({
        model: 'models/text-bison-001',
        prompt: { text: prompt },
      });

      if (!result || !result[0] || !result[0].candidates || result[0].candidates.length === 0) {
        if (result[0].filters && result[0].filters.length > 0) {
          console.log(`Content filtered. Reason: ${result[0].filters[0].reason}. Retrying with modified prompt.`);
          continue;
        }
        throw new Error('Unexpected response structure from Gemini API');
      }

      const response = result[0].candidates[0].output || {};
      return res.json({ pii: response });
    } catch (error) {
      console.error(`Error in attempt ${attempt + 1}:`, error);
      if (attempt === MAX_RETRIES - 1) {
        return res.status(500).json({
          error: 'Failed to get response from Gemini after multiple attempts',
          details: error.message
        });
      }
    }
  }
});

app.use('/api/auth', authRoutes);

app.get('/google-client-id', (req, res) => {
  res.json({ clientId: process.env.GOOGLE_CLIENT_ID });
});

app.listen(port, () => {
  connectToMongoDB();
  logger.info(`Server is running on http://localhost:${port}`);
});

function analyzeLogContent(logContent) {
  const stats = {
    totalLines: 0,
  };

  const lines = logContent.split('\n');
  stats.totalLines = lines.length;
  return stats;
}