PGDMP         +                {        	   ProjektBD    15.2    15.2 0    /           0    0    ENCODING    ENCODING        SET client_encoding = 'UTF8';
                      false            0           0    0 
   STDSTRINGS 
   STDSTRINGS     (   SET standard_conforming_strings = 'on';
                      false            1           0    0 
   SEARCHPATH 
   SEARCHPATH     8   SELECT pg_catalog.set_config('search_path', '', false);
                      false            2           1262    16399 	   ProjektBD    DATABASE     ~   CREATE DATABASE "ProjektBD" WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE_PROVIDER = libc LOCALE = 'Polish_Poland.1250';
    DROP DATABASE "ProjektBD";
                barte    false            �            1259    32835    appusers    TABLE     7  CREATE TABLE public.appusers (
    id bigint NOT NULL,
    name character varying(100) NOT NULL,
    surname character varying(100) NOT NULL,
    email character varying(100) NOT NULL,
    password character varying(1000) NOT NULL,
    class character varying(100) DEFAULT 'user'::character varying NOT NULL
);
    DROP TABLE public.appusers;
       public         heap    barte    false            �            1259    32841    appusers_id_seq    SEQUENCE     x   CREATE SEQUENCE public.appusers_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 &   DROP SEQUENCE public.appusers_id_seq;
       public          barte    false    214            3           0    0    appusers_id_seq    SEQUENCE OWNED BY     C   ALTER SEQUENCE public.appusers_id_seq OWNED BY public.appusers.id;
          public          barte    false    215            �            1259    32886    document_owner    TABLE     �   CREATE TABLE public.document_owner (
    id_owner_docown bigint NOT NULL,
    id_document_docown bigint NOT NULL,
    id_user_docown bigint NOT NULL
);
 "   DROP TABLE public.document_owner;
       public         heap    postgres    false            �            1259    32885    document_owner_doc_owner_id_seq    SEQUENCE     �   CREATE SEQUENCE public.document_owner_doc_owner_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 6   DROP SEQUENCE public.document_owner_doc_owner_id_seq;
       public          postgres    false    225            4           0    0    document_owner_doc_owner_id_seq    SEQUENCE OWNED BY     f   ALTER SEQUENCE public.document_owner_doc_owner_id_seq OWNED BY public.document_owner.id_owner_docown;
          public          postgres    false    224            �            1259    32842 	   documents    TABLE       CREATE TABLE public.documents (
    id_document bigint NOT NULL,
    id_user_document bigint NOT NULL,
    title_document character varying(100) NOT NULL,
    note_document character varying(1000),
    date_document timestamp(6) with time zone NOT NULL,
    id_file_document bigint
);
    DROP TABLE public.documents;
       public         heap    postgres    false            �            1259    32847    documents_document_id_seq    SEQUENCE     �   CREATE SEQUENCE public.documents_document_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 0   DROP SEQUENCE public.documents_document_id_seq;
       public          postgres    false    216            5           0    0    documents_document_id_seq    SEQUENCE OWNED BY     W   ALTER SEQUENCE public.documents_document_id_seq OWNED BY public.documents.id_document;
          public          postgres    false    217            �            1259    32848    file_archive_del    TABLE     �   CREATE TABLE public.file_archive_del (
    id_arch_filarchdel bigint NOT NULL,
    date_arch_filarchdel timestamp(6) with time zone NOT NULL,
    id_user_arch_filarchdel bigint NOT NULL,
    file_id_filarchdel bigint NOT NULL
);
 $   DROP TABLE public.file_archive_del;
       public         heap    barte    false            �            1259    32851     file_archive_id_file_archive_seq    SEQUENCE     �   CREATE SEQUENCE public.file_archive_id_file_archive_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 7   DROP SEQUENCE public.file_archive_id_file_archive_seq;
       public          barte    false    218            6           0    0     file_archive_id_file_archive_seq    SEQUENCE OWNED BY     l   ALTER SEQUENCE public.file_archive_id_file_archive_seq OWNED BY public.file_archive_del.id_arch_filarchdel;
          public          barte    false    219            �            1259    32856 
   file_owner    TABLE     �   CREATE TABLE public.file_owner (
    id_owner_filown bigint NOT NULL,
    id_user_filown integer NOT NULL,
    id_file_filown integer NOT NULL
);
    DROP TABLE public.file_owner;
       public         heap    barte    false            �            1259    32852    files    TABLE     (  CREATE TABLE public.files (
    id_file bigint NOT NULL,
    name_file character varying(100) NOT NULL,
    hashed_name_file character varying(300) NOT NULL,
    upload_timestamp timestamp(6) with time zone NOT NULL,
    size_file bigint NOT NULL,
    type_file character varying(10) NOT NULL
);
    DROP TABLE public.files;
       public         heap    barte    false            �            1259    32855    files_id_file_seq    SEQUENCE     z   CREATE SEQUENCE public.files_id_file_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 (   DROP SEQUENCE public.files_id_file_seq;
       public          barte    false    220            7           0    0    files_id_file_seq    SEQUENCE OWNED BY     G   ALTER SEQUENCE public.files_id_file_seq OWNED BY public.files.id_file;
          public          barte    false    221            �            1259    32859    owners_id_owner_seq    SEQUENCE     |   CREATE SEQUENCE public.owners_id_owner_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 *   DROP SEQUENCE public.owners_id_owner_seq;
       public          barte    false    222            8           0    0    owners_id_owner_seq    SEQUENCE OWNED BY     V   ALTER SEQUENCE public.owners_id_owner_seq OWNED BY public.file_owner.id_owner_filown;
          public          barte    false    223            ~           2604    32892    appusers id    DEFAULT     j   ALTER TABLE ONLY public.appusers ALTER COLUMN id SET DEFAULT nextval('public.appusers_id_seq'::regclass);
 :   ALTER TABLE public.appusers ALTER COLUMN id DROP DEFAULT;
       public          barte    false    215    214            �           2604    32889    document_owner id_owner_docown    DEFAULT     �   ALTER TABLE ONLY public.document_owner ALTER COLUMN id_owner_docown SET DEFAULT nextval('public.document_owner_doc_owner_id_seq'::regclass);
 M   ALTER TABLE public.document_owner ALTER COLUMN id_owner_docown DROP DEFAULT;
       public          postgres    false    224    225    225            �           2604    32893    documents id_document    DEFAULT     ~   ALTER TABLE ONLY public.documents ALTER COLUMN id_document SET DEFAULT nextval('public.documents_document_id_seq'::regclass);
 D   ALTER TABLE public.documents ALTER COLUMN id_document DROP DEFAULT;
       public          postgres    false    217    216            �           2604    32894 #   file_archive_del id_arch_filarchdel    DEFAULT     �   ALTER TABLE ONLY public.file_archive_del ALTER COLUMN id_arch_filarchdel SET DEFAULT nextval('public.file_archive_id_file_archive_seq'::regclass);
 R   ALTER TABLE public.file_archive_del ALTER COLUMN id_arch_filarchdel DROP DEFAULT;
       public          barte    false    219    218            �           2604    32896    file_owner id_owner_filown    DEFAULT     }   ALTER TABLE ONLY public.file_owner ALTER COLUMN id_owner_filown SET DEFAULT nextval('public.owners_id_owner_seq'::regclass);
 I   ALTER TABLE public.file_owner ALTER COLUMN id_owner_filown DROP DEFAULT;
       public          barte    false    223    222            �           2604    32895    files id_file    DEFAULT     n   ALTER TABLE ONLY public.files ALTER COLUMN id_file SET DEFAULT nextval('public.files_id_file_seq'::regclass);
 <   ALTER TABLE public.files ALTER COLUMN id_file DROP DEFAULT;
       public          barte    false    221    220            !          0    32835    appusers 
   TABLE DATA           M   COPY public.appusers (id, name, surname, email, password, class) FROM stdin;
    public          barte    false    214   �7       ,          0    32886    document_owner 
   TABLE DATA           ]   COPY public.document_owner (id_owner_docown, id_document_docown, id_user_docown) FROM stdin;
    public          postgres    false    225   78       #          0    32842 	   documents 
   TABLE DATA           �   COPY public.documents (id_document, id_user_document, title_document, note_document, date_document, id_file_document) FROM stdin;
    public          postgres    false    216   T8       %          0    32848    file_archive_del 
   TABLE DATA           �   COPY public.file_archive_del (id_arch_filarchdel, date_arch_filarchdel, id_user_arch_filarchdel, file_id_filarchdel) FROM stdin;
    public          barte    false    218   q8       )          0    32856 
   file_owner 
   TABLE DATA           U   COPY public.file_owner (id_owner_filown, id_user_filown, id_file_filown) FROM stdin;
    public          barte    false    222   �8       '          0    32852    files 
   TABLE DATA           m   COPY public.files (id_file, name_file, hashed_name_file, upload_timestamp, size_file, type_file) FROM stdin;
    public          barte    false    220   �8       9           0    0    appusers_id_seq    SEQUENCE SET     =   SELECT pg_catalog.setval('public.appusers_id_seq', 8, true);
          public          barte    false    215            :           0    0    document_owner_doc_owner_id_seq    SEQUENCE SET     N   SELECT pg_catalog.setval('public.document_owner_doc_owner_id_seq', 62, true);
          public          postgres    false    224            ;           0    0    documents_document_id_seq    SEQUENCE SET     H   SELECT pg_catalog.setval('public.documents_document_id_seq', 52, true);
          public          postgres    false    217            <           0    0     file_archive_id_file_archive_seq    SEQUENCE SET     N   SELECT pg_catalog.setval('public.file_archive_id_file_archive_seq', 8, true);
          public          barte    false    219            =           0    0    files_id_file_seq    SEQUENCE SET     @   SELECT pg_catalog.setval('public.files_id_file_seq', 76, true);
          public          barte    false    221            >           0    0    owners_id_owner_seq    SEQUENCE SET     B   SELECT pg_catalog.setval('public.owners_id_owner_seq', 72, true);
          public          barte    false    223            �           2606    32866    appusers appusers_pkey 
   CONSTRAINT     T   ALTER TABLE ONLY public.appusers
    ADD CONSTRAINT appusers_pkey PRIMARY KEY (id);
 @   ALTER TABLE ONLY public.appusers DROP CONSTRAINT appusers_pkey;
       public            barte    false    214            �           2606    32891 "   document_owner document_owner_pkey 
   CONSTRAINT     m   ALTER TABLE ONLY public.document_owner
    ADD CONSTRAINT document_owner_pkey PRIMARY KEY (id_owner_docown);
 L   ALTER TABLE ONLY public.document_owner DROP CONSTRAINT document_owner_pkey;
       public            postgres    false    225            �           2606    32868    documents documents_pkey 
   CONSTRAINT     _   ALTER TABLE ONLY public.documents
    ADD CONSTRAINT documents_pkey PRIMARY KEY (id_document);
 B   ALTER TABLE ONLY public.documents DROP CONSTRAINT documents_pkey;
       public            postgres    false    216            �           2606    32870 "   file_archive_del file_archive_pkey 
   CONSTRAINT     p   ALTER TABLE ONLY public.file_archive_del
    ADD CONSTRAINT file_archive_pkey PRIMARY KEY (id_arch_filarchdel);
 L   ALTER TABLE ONLY public.file_archive_del DROP CONSTRAINT file_archive_pkey;
       public            barte    false    218            �           2606    32872    files files_pkey 
   CONSTRAINT     S   ALTER TABLE ONLY public.files
    ADD CONSTRAINT files_pkey PRIMARY KEY (id_file);
 :   ALTER TABLE ONLY public.files DROP CONSTRAINT files_pkey;
       public            barte    false    220            �           2606    32874    file_owner owners_pkey 
   CONSTRAINT     a   ALTER TABLE ONLY public.file_owner
    ADD CONSTRAINT owners_pkey PRIMARY KEY (id_owner_filown);
 @   ALTER TABLE ONLY public.file_owner DROP CONSTRAINT owners_pkey;
       public            barte    false    222            �           2606    32875    file_owner owners_id_file_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.file_owner
    ADD CONSTRAINT owners_id_file_fkey FOREIGN KEY (id_file_filown) REFERENCES public.files(id_file);
 H   ALTER TABLE ONLY public.file_owner DROP CONSTRAINT owners_id_file_fkey;
       public          barte    false    220    3212    222            �           2606    32880    file_owner owners_id_user_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.file_owner
    ADD CONSTRAINT owners_id_user_fkey FOREIGN KEY (id_user_filown) REFERENCES public.appusers(id);
 H   ALTER TABLE ONLY public.file_owner DROP CONSTRAINT owners_id_user_fkey;
       public          barte    false    214    3206    222            !   5   x�3�tJ,*I��tN-I-J�L�����s3s���s9K�S��W� å`      ,      x������ � �      #      x������ � �      %      x������ � �      )      x������ � �      '      x������ � �     