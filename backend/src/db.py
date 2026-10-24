
import os
import psycopg

def get_connection():
    return psycopg.connect(
        host=os.getenv("DB_HOST", "postgres"),
        port=int(os.getenv("DB_PORT", "5432")),
        dbname=os.getenv("DB_NAME", "app_db"),
        user=os.getenv("DB_USER", "app_user"),
        password=os.environ["DB_PASSWORD"],
    )

def init_db():
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'user',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);""")
            cur.execute("""CREATE TABLE IF NOT EXISTS applications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id),
    company_data JSONB NOT NULL,
    selected_product_id UUID NOT NULL REFERENCES loan_products(id),
    original_terms JSONB NOT NULL,
    active_terms JSON NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('draft', 'pending', 'in_review', 'approved', 'alternative_offered', 'rejected')),
    rejection_cause TEXT,
    submitted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTANPTZ
);""")
            cur.execute("""CREATE TABLE IF NOT EXISTS loan_products (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    purpose VARCHAR(255) NOT NULL,
    description TEXT,
    min_amount FLOAT,
    max_amount FLOAT,
    min_term_months INTEGER,
    max_term_months INTEGER,
    annual_rate FLOAT,
    is_active BOOLEAN
);""")
            cur.execute("""CREATE TABLE IF NOT EXISTS documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID NOT NULL REFERENCES applications(id),
    document_type VARCHAR(255) NOT NULL,
    original_name TEXT NOT NULL,
    storage_path VARCHAR(255) NOT NULL,
    mime_type VARCHAR(255) NOT NULL,
    uploaded_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);""")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS alternative_offers (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    application_id UUID NOT NULL
                        REFERENCES applications(id),
                    employee_id UUID NOT NULL
                        REFERENCES users(id),
                    product_id UUID NOT NULL
                        REFERENCES loan_products(id),
                    amount NUMERIC(15, 2) NOT NULL
                        CHECK (amount > 0),
                    term_months INTEGER NOT NULL
                        CHECK (term_months > 0),
                    annual_rate NUMERIC(5, 2) NOT NULL
                        CHECK (annual_rate >= 0),
                    comment TEXT,
                    response VARCHAR(20) DEFAULT 'pending'
                        CHECK (response IN ('pending', 'accepted', 'rejected')),
                    responded_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ NOT NULL
                        DEFAULT CURRENT_TIMESTAMP
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS application_history (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    application_id UUID NOT NULL
                        REFERENCES applications(id),
                    actor_id UUID REFERENCES users(id),
                    event_type VARCHAR(100) NOT NULL,
                    details JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_at TIMESTAMPTZ NOT NULL
                        DEFAULT CURRENT_TIMESTAMP
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS mock_companies (
                    inn VARCHAR(12) PRIMARY KEY,
                    company_name VARCHAR(255) NOT NULL,
                    ogrn VARCHAR(15) UNIQUE,
                    address TEXT,
                    okved JSONB
                );
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_alternative_offers_application
                    ON alternative_offers(application_id);

                CREATE INDEX IF NOT EXISTS idx_application_history_application
                    ON application_history(application_id);

                CREATE INDEX IF NOT EXISTS idx_application_history_created_at
                    ON application_history(created_at);
            """)
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS auth_sessions (
                    id UUID PRIMARY KEY,
                    user_id UUID NOT NULL
                        REFERENCES users(id) ON DELETE CASCADE,
                    refresh_token_hash TEXT NOT NULL,
                    expires_at TIMESTAMPTZ NOT NULL,
                    revoked_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
            cur.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_auth_sessions_user_id
                ON auth_sessions(user_id)
                """
            )