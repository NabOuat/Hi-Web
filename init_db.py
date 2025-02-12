from dotenv import load_dotenv
import os
from supabase import create_client, Client

# Load environment variables
load_dotenv()

# Initialize Supabase client
url = os.getenv('SUPABASE_URL')
key = os.getenv('SUPABASE_KEY')
supabase: Client = create_client(url, key)

# Création de la table activity_log
create_activity_log_table = """
CREATE TABLE IF NOT EXISTS activity_log (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    action VARCHAR NOT NULL,
    details JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    directory_id UUID REFERENCES directories(id) ON DELETE CASCADE
);

-- Index pour améliorer les performances des requêtes
CREATE INDEX IF NOT EXISTS idx_activity_log_user_id ON activity_log(user_id);
CREATE INDEX IF NOT EXISTS idx_activity_log_directory_id ON activity_log(directory_id);
CREATE INDEX IF NOT EXISTS idx_activity_log_created_at ON activity_log(created_at);

-- Supprimer les politiques existantes
DROP POLICY IF EXISTS activity_log_superadmin_policy ON activity_log;
DROP POLICY IF EXISTS activity_log_admin_policy ON activity_log;
DROP POLICY IF EXISTS activity_log_user_policy ON activity_log;

-- Politique de sécurité RLS pour activity_log
ALTER TABLE activity_log ENABLE ROW LEVEL SECURITY;

-- Les superadmins peuvent tout voir
CREATE POLICY activity_log_superadmin_policy ON activity_log
    FOR ALL
    TO authenticated
    USING (
        EXISTS (
            SELECT 1 FROM users
            WHERE users.id = auth.uid()
            AND users.role = 'superadmin'
        )
    );

-- Les admins peuvent voir les activités de leur répertoire
CREATE POLICY activity_log_admin_policy ON activity_log
    FOR ALL
    TO authenticated
    USING (
        EXISTS (
            SELECT 1 FROM user_access
            WHERE user_access.user_id = auth.uid()
            AND user_access.role_in_dir = 'admin'
            AND user_access.directory_id = activity_log.directory_id
        )
    );

-- Les utilisateurs peuvent voir leurs propres activités
CREATE POLICY activity_log_user_policy ON activity_log
    FOR SELECT
    TO authenticated
    USING (
        user_id = auth.uid()
    );
"""

# Création de la table files
create_files_table = """
-- Supprimer la table si elle existe
DROP TABLE IF EXISTS files CASCADE;

CREATE TABLE files (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    filename VARCHAR NOT NULL,
    file_size BIGINT NOT NULL,
    mime_type VARCHAR,
    directory_id UUID REFERENCES directories(id) ON DELETE CASCADE,
    uploaded_by UUID REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Index pour améliorer les performances
CREATE INDEX IF NOT EXISTS idx_files_directory_id ON files(directory_id);
CREATE INDEX IF NOT EXISTS idx_files_uploaded_by ON files(uploaded_by);
CREATE INDEX IF NOT EXISTS idx_files_created_at ON files(created_at);
"""

# Politiques de sécurité pour files
create_files_policies = """
-- Politique de sécurité RLS pour files
ALTER TABLE files ENABLE ROW LEVEL SECURITY;

-- Les superadmins peuvent tout voir
CREATE POLICY files_superadmin_policy ON files
    FOR ALL
    TO authenticated
    USING (
        EXISTS (
            SELECT 1 FROM users
            WHERE users.id = auth.uid()
            AND users.role = 'superadmin'
        )
    );

-- Les admins peuvent voir les fichiers de leur répertoire
CREATE POLICY files_admin_policy ON files
    FOR ALL
    TO authenticated
    USING (
        EXISTS (
            SELECT 1 FROM user_access
            WHERE user_access.user_id = auth.uid()
            AND user_access.role_in_dir = 'admin'
            AND user_access.directory_id = files.directory_id
        )
    );

-- Les utilisateurs peuvent voir leurs propres fichiers
CREATE POLICY files_user_policy ON files
    FOR ALL
    TO authenticated
    USING (
        uploaded_by = auth.uid()
        OR
        EXISTS (
            SELECT 1 FROM user_access
            WHERE user_access.user_id = auth.uid()
            AND user_access.directory_id = files.directory_id
        )
    );
"""

# Ajout de la clé étrangère à user_access
add_user_access_foreign_key = """
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints 
        WHERE constraint_name = 'fk_user_access_user'
    ) THEN
        ALTER TABLE user_access 
        ADD CONSTRAINT fk_user_access_user
        FOREIGN KEY (user_id) 
        REFERENCES users(id)
        ON DELETE CASCADE;
    END IF;
END $$;
"""

# Ajout de la colonne storage_quota à la table users
add_storage_quota = """
ALTER TABLE users
ADD COLUMN IF NOT EXISTS storage_quota BIGINT DEFAULT 1073741824;  -- 1GB par défaut
"""

# Ajout de la colonne storage_used à la table users
add_storage_used = """
ALTER TABLE users
ADD COLUMN IF NOT EXISTS storage_used BIGINT DEFAULT 0;
"""

# Fonction pour mettre à jour storage_used
create_update_storage_used_function = """
CREATE OR REPLACE FUNCTION update_user_storage_used()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        UPDATE users
        SET storage_used = storage_used + NEW.file_size
        WHERE id = NEW.uploaded_by;
    ELSIF TG_OP = 'DELETE' THEN
        UPDATE users
        SET storage_used = storage_used - OLD.file_size
        WHERE id = OLD.uploaded_by;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;
"""

# Trigger pour mettre à jour storage_used
create_storage_used_trigger = """
DROP TRIGGER IF EXISTS update_storage_used_trigger ON files;
CREATE TRIGGER update_storage_used_trigger
AFTER INSERT OR DELETE ON files
FOR EACH ROW
EXECUTE FUNCTION update_user_storage_used();
"""

def init_db():
    try:
        # Exécuter les requêtes SQL
        supabase.table('users').select("*").limit(1).execute()  # Vérifier la connexion
        
        # Créer la table files
        supabase.rpc('exec_sql', {'sql': create_files_table}).execute()
        
        # Créer les politiques pour files
        supabase.rpc('exec_sql', {'sql': create_files_policies}).execute()
        
        # Créer la table activity_log et ses index
        supabase.rpc('exec_sql', {'sql': create_activity_log_table}).execute()
        
        # Ajouter la clé étrangère à user_access
        supabase.rpc('exec_sql', {'sql': add_user_access_foreign_key}).execute()
        
        # Ajouter les colonnes de stockage à la table users
        supabase.rpc('exec_sql', {'sql': add_storage_quota}).execute()
        supabase.rpc('exec_sql', {'sql': add_storage_used}).execute()
        
        # Créer la fonction et le trigger pour storage_used
        supabase.rpc('exec_sql', {'sql': create_update_storage_used_function}).execute()
        supabase.rpc('exec_sql', {'sql': create_storage_used_trigger}).execute()
        
        print("Base de données initialisée avec succès!")
        
    except Exception as e:
        print(f"Erreur lors de l'initialisation de la base de données: {str(e)}")
        raise e

if __name__ == "__main__":
    init_db()
