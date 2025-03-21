from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey, JSON, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import logging
import os

logger = logging.getLogger(__name__)

Base = declarative_base()

class Scan(Base):
    """Model for storing scan information."""
    __tablename__ = 'scans'
    
    id = Column(Integer, primary_key=True)
    domain = Column(String, nullable=False)
    scan_type = Column(String, nullable=False)
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime)
    status = Column(String, default='running')
    findings = relationship('Finding', back_populates='scan')

class Finding(Base):
    """Model for storing scan findings."""
    __tablename__ = 'findings'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id'))
    type = Column(String, nullable=False)  # subdomain, vulnerability, endpoint, etc.
    name = Column(String)
    severity = Column(String)
    description = Column(String)
    evidence = Column(String)
    metadata = Column(JSON)  # For flexible additional data
    discovered_at = Column(DateTime, default=datetime.utcnow)
    scan = relationship('Scan', back_populates='findings')

class Database:
    """Database handler for ReconBuddy."""
    
    def __init__(self, connection_string=None):
        """Initialize database connection."""
        if not connection_string:
            # Default to environment variable or local development database
            connection_string = os.getenv(
                'RECONBUDDY_DB_URL',
                'postgresql://postgres:postgres@localhost:5432/reconbuddy'
            )
        
        try:
            self.engine = create_engine(connection_string)
            Base.metadata.create_all(self.engine)
            self.Session = sessionmaker(bind=self.engine)
            logger.info("Database connection established successfully")
        except Exception as e:
            logger.error(f"Failed to initialize database: {str(e)}")
            raise
    
    def create_scan(self, domain: str, scan_type: str) -> Scan:
        """Create a new scan record."""
        try:
            session = self.Session()
            scan = Scan(domain=domain, scan_type=scan_type)
            session.add(scan)
            session.commit()
            logger.info(f"Created new scan for domain: {domain}")
            return scan
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to create scan: {str(e)}")
            raise
        finally:
            session.close()
    
    def update_scan_status(self, scan_id: int, status: str, end_time: datetime = None) -> None:
        """Update scan status and end time."""
        try:
            session = self.Session()
            scan = session.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = status
                if end_time:
                    scan.end_time = end_time
                session.commit()
                logger.info(f"Updated scan {scan_id} status to: {status}")
            else:
                logger.warning(f"Scan {scan_id} not found")
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to update scan status: {str(e)}")
            raise
        finally:
            session.close()
    
    def add_finding(self, scan_id: int, finding_type: str, **kwargs) -> Finding:
        """Add a new finding to a scan."""
        try:
            session = self.Session()
            finding = Finding(
                scan_id=scan_id,
                type=finding_type,
                name=kwargs.get('name'),
                severity=kwargs.get('severity'),
                description=kwargs.get('description'),
                evidence=kwargs.get('evidence'),
                metadata=kwargs.get('metadata', {})
            )
            session.add(finding)
            session.commit()
            logger.info(f"Added new finding to scan {scan_id}")
            return finding
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to add finding: {str(e)}")
            raise
        finally:
            session.close()
    
    def get_scan(self, scan_id: int) -> Scan:
        """Get scan by ID."""
        try:
            session = self.Session()
            scan = session.query(Scan).filter(Scan.id == scan_id).first()
            return scan
        finally:
            session.close()
    
    def get_findings(self, scan_id: int, finding_type: str = None) -> list:
        """Get findings for a scan, optionally filtered by type."""
        try:
            session = self.Session()
            query = session.query(Finding).filter(Finding.scan_id == scan_id)
            if finding_type:
                query = query.filter(Finding.type == finding_type)
            return query.all()
        finally:
            session.close()
    
    def get_scans_by_domain(self, domain: str) -> list:
        """Get all scans for a domain."""
        try:
            session = self.Session()
            return session.query(Scan).filter(Scan.domain == domain).all()
        finally:
            session.close()
    
    def delete_scan(self, scan_id: int) -> bool:
        """Delete a scan and its findings."""
        try:
            session = self.Session()
            scan = session.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                session.delete(scan)
                session.commit()
                logger.info(f"Deleted scan {scan_id}")
                return True
            return False
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to delete scan: {str(e)}")
            raise
        finally:
            session.close() 