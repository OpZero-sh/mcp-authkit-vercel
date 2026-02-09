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

    // Split by semicolons and filter out empty statements
    const statements = schema
      .split(';')
      .map(s => s.trim())
      .filter(s => s.length > 0 && !s.startsWith('--'));

    console.log(`📝 Executing ${statements.length} SQL statements...\n`);

    for (const statement of statements) {
      // Skip comments
      if (statement.startsWith('--')) continue;

      try {
        await db.execute(statement);
        // Extract table name from CREATE TABLE statement
        const match = statement.match(/CREATE\s+(?:TABLE|INDEX)(?:\s+IF\s+NOT\s+EXISTS)?\s+(\w+)/i);
        if (match) {
          console.log(`✅ Created: ${match[1]}`);
        }
      } catch (err) {
        console.error(`❌ Error executing statement:`, err.message);
        console.error(`Statement: ${statement.substring(0, 100)}...`);
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
