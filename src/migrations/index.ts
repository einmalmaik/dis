/**
 * dis-migrations — explicit, ordered transformation of encrypted payloads.
 *
 * Migrations are registered against a (subject, fromVersion) key and run in a
 * deterministic order. This gives applications a single, testable place to
 * evolve formats (e.g. re-wrap legacy no-AAD vault items, bump KDF parameters,
 * re-encrypt under a new cipher) without scattering ad-hoc upgrade code.
 *
 * DIS provides the framework and the crypto; the application decides which
 * migrations to register and how persistence happens.
 */

import { DisError, DisInvalidArgumentError } from '../core/errors.js';

/** Context passed to a migration step. `key` material is caller-supplied. */
export interface MigrationContext {
    readonly key: CryptoKey;
    /** Stable identifier the payload is bound to (e.g. entry id). */
    readonly bindingId?: string;
}

/** A single migration: transforms a payload from `fromVersion` to `toVersion`. */
export interface Migration {
    readonly subject: string;
    readonly fromVersion: number | 'legacy';
    readonly toVersion: number;
    /** Returns the migrated payload string. Must be idempotent on its output. */
    migrate(payload: string, context: MigrationContext): Promise<string>;
}

/** Detects the current version of a payload for a subject. */
export type VersionDetector = (payload: string) => number | 'legacy';

/** An ordered registry of migrations for one or more subjects. */
export class MigrationRegistry {
    private readonly migrations = new Map<string, Migration>();

    private keyOf(subject: string, fromVersion: number | 'legacy'): string {
        return `${subject}@${fromVersion}`;
    }

    /** Registers a migration. Throws if one already exists for the same step. */
    register(migration: Migration): this {
        const key = this.keyOf(migration.subject, migration.fromVersion);
        if (this.migrations.has(key)) {
            throw new DisInvalidArgumentError(`Duplicate migration for ${key}`);
        }
        this.migrations.set(key, migration);
        return this;
    }

    /**
     * Applies all applicable migrations in sequence until no further migration
     * exists for the payload's detected version. Guards against cycles.
     */
    async migrateToLatest(
        subject: string,
        payload: string,
        detect: VersionDetector,
        context: MigrationContext,
    ): Promise<string> {
        let current = payload;
        const seen = new Set<number | 'legacy'>();
        for (;;) {
            const version = detect(current);
            if (seen.has(version)) {
                throw new DisError(
                    'INVALID_ARGUMENT',
                    `Migration cycle detected for ${subject}@${version}`,
                );
            }
            seen.add(version);
            const migration = this.migrations.get(this.keyOf(subject, version));
            if (!migration) return current;
            current = await migration.migrate(current, context);
        }
    }
}
