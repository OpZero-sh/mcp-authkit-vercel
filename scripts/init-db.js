#!/usr/bin/env node

/**
 * Database initialization script for Turso
 * Reads schema.sql and applies it to your Turso database
 */

import { createClient } from '@libsql/client';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

async function initDatabase() {
  // Load environment variables
  const TURSO_DATABASE_URL = process.env.TURSO_DATABASE_URL;
  const TURSO_AUTH_TOKEN = process.env.TURSO_AUTH_TOKEN;

  if (!TURSO_DATABASE_URL || !TURSO_AUTH_TOKEN) {
    console.error('❌ Error: TURSO_DATABASE_URL and TURSO_AUTH_TOKEN must be set');
    console.error('\nSet them in your .env file or environment:');
    console.error('  TURSO_DATABASE_URL=libsql://your-db-name.turso.io');
    console.error('  TURSO_AUTH_TOKEN=your-auth-token');
    process.exit(1);
  }

  console.log('🔄 Connecting to Turso database...');
  const db = createClient({
    url: TURSO_DATABASE_URL,
    authToken: TURSO_AUTH_TOKEN,
  });

  try {
    // Read schema file
    const schemaPath = join(__dirname, '..', 'schema.sql');
    const schema = readFileSync(schemaPath, 'utf8');

    console.log('📝 Executing schema...\n');

    // Remove comments and split into proper SQL statements
    const lines = schema.split('\n');
    let currentStatement = '';
    const statements = [];

    for (const line of lines) {
      const trimmed = line.trim();
      // Skip comment-only lines
      if (trimmed.startsWith('--') || trimmed === '') continue;

      currentStatement += ' ' + line;

      // If line ends with semicolon (and isn't in middle of a statement), it's complete
      if (trimmed.endsWith(';')) {
        statements.push(currentStatement.trim());
        currentStatement = '';
      }
    }

    console.log(`Executing ${statements.length} SQL statements...\n`);

    // Execute each statement
    for (const stmt of statements) {
      try {
        await db.execute(stmt);
        const match = stmt.match(/CREATE\s+(?:TABLE|INDEX)(?:\s+IF\s+NOT\s+EXISTS)?\s+(\w+)/i);
        if (match) {
          console.log(`✅ Created: ${match[1]}`);
        }
      } catch (err) {
        console.error(`❌ Error:`, err.message);
        console.error(`Statement: ${stmt.substring(0, 80)}...`);
      }
    }

    console.log('\n✨ Database initialized successfully!');
    console.log('\nNext steps:');
    console.log('  1. Deploy to Vercel: npm run deploy');
    console.log('  2. Set environment variables in Vercel dashboard');
    console.log('  3. Register your first MCP server via POST /api/auth/api/servers');

  } catch (err) {
    console.error('❌ Error:', err.message);
    process.exit(1);
  }
}

initDatabase();
