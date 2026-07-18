/**
 * Banksia OS — Drizzle ORM Reference Schema
 * 
 * Mirrors the SQLite schema for future PostgreSQL migration.
 * This file is a REFERENCE only — not imported by the app.
 * 
 * Migration path:
 * 1. pnpm add drizzle-orm @neondatabase/serverless
 * 2. Set DATABASE_URL in .env.local
 * 3. npx drizzle-kit generate && npx drizzle-kit migrate
 * 
 * Until then, all API calls go through Flask (/api/banksia-os).
 */

import { sqliteTable, text, integer, real } from 'drizzle-orm/sqlite-core';

export const properties = sqliteTable('properties', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  name: text('name'),
  ref: text('ref'),
  address_line_1: text('address_line_1'),
  address_line_2: text('address_line_2'),
  city: text('city'),
  postcode: text('postcode'),
  country: text('country').default('United Kingdom'),
  property_type: text('property_type'),
  status: text('status').default('Active'),
  property_owner_id: integer('property_owner_id'),
  is_active: integer('is_active').default(1),
  created: text('created'),
  modified: text('modified'),
  unit_count: integer('unit_count'),
  management_fee_percent: real('management_fee_percent'),
  sync_dirty: integer('sync_dirty').default(0),
});

export const units = sqliteTable('units', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  property_id: integer('property_id'),
  ref: text('ref'),
  unit_ref: text('unit_ref'),
  unit_vacant: integer('unit_vacant').default(1),
  market_rent: real('market_rent'),
  sort_order: integer('sort_order'),
  is_active: integer('is_active').default(1),
  created: text('created'),
  modified: text('modified'),
  sync_dirty: integer('sync_dirty').default(0),
});

export const tenancies = sqliteTable('tenancies', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  property_id: integer('property_id'),
  unit_id: integer('unit_id'),
  ref: text('ref'),
  main_tenant_name: text('main_tenant_name'),
  rent_amount: real('rent_amount'),
  rent_frequency: text('rent_frequency'),
  deposit_amount: real('deposit_amount'),
  status: text('status'),
  move_in_date: text('move_in_date'),
  move_out_date: text('move_out_date'),
  is_active: integer('is_active').default(1),
  created: text('created'),
  sync_dirty: integer('sync_dirty').default(0),
});

export const transactions = sqliteTable('transactions', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  tenancy_id: integer('tenancy_id'),
  property_id: integer('property_id'),
  amount: real('amount'),
  amount_outstanding: real('amount_outstanding'),
  type: text('type'),
  description: text('description'),
  transaction_date: text('transaction_date'),
  is_outstanding: integer('is_outstanding').default(1),
  created: text('created'),
});

export const deposits = sqliteTable('deposits', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  tenancy_id: integer('tenancy_id'),
  property_id: integer('property_id'),
  amount: real('amount'),
  protection_status: text('protection_status'),
  protection_scheme: text('protection_scheme'),
  protection_ref: text('protection_ref'),
  current_status: text('current_status'),
  created: text('created'),
});

export const maintenanceJobs = sqliteTable('maintenance_jobs', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  property_id: integer('property_id'),
  unit_id: integer('unit_id'),
  description: text('description'),
  priority: integer('priority').default(0),
  status: text('status').default('open'),
  category: text('category'),
  assigned_to: text('assigned_to'),
  estimated_cost: real('estimated_cost'),
  landlord_informed: integer('landlord_informed').default(0),
  bill_landlord: integer('bill_landlord').default(0),
  is_active: integer('is_active').default(1),
  created: text('created'),
  modified: text('modified'),
});

export const notifications = sqliteTable('notifications', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  username: text('username'),
  message: text('message'),
  link: text('link'),
  is_read: integer('is_read').default(0),
  created_at: text('created_at'),
});

export const authAuditLog = sqliteTable('auth_audit_log', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  event_type: text('event_type'),
  username: text('username'),
  details: text('details'),
  ip_address: text('ip_address'),
  created_at: text('created_at'),
});
